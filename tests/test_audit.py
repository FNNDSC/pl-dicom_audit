"""
Integration tests: main() over trees anonymized in-process with the real
dicom-anonymizer engine.
"""

import csv
import datetime as dt
import hashlib
import json

import pydicom
import pytest
from pydicom.uid import generate_uid

from conftest import (ANON, ORIG, PHI_STRINGS, anonymize_tree, codes, make_dcm, read_jsonl,
                      rewrite, summary)
from dicom_audit import main


def rows(path):
    with open(path, newline="") as fh:
        return list(csv.DictReader(fh))


def run(options, inputdir, outdir):
    """Run main; return the exit code (0 when it returned normally)."""
    try:
        main(options, inputdir, outdir)
    except SystemExit as e:
        return e.code
    return 0


# --------------------------------------------------------------------------
# Clean run
# --------------------------------------------------------------------------

def test_clean_run_passes(anonymized, outdir, options):
    assert run(options, anonymized, outdir) == 0
    s = summary(outdir)
    assert s["overall_status"] == "pass"
    assert s["files"]["by_status"] == {"audited": 4, "redaction_sidecar": 1}
    assert s["files"]["pairing_complete"] is True
    assert s["patients"]["count"] == 2
    assert s["accessions"] == 2
    assert s["uids"]["by_level"] == {"series": 3, "sop": 4, "study": 2}
    assert s["pixels"]["integrity"] == {"match": 4}
    assert s["leaks"]["file_hashes"] == []
    assert s["anonymizer"]["overall_status"] == "success"


def test_output_layout(anonymized, outdir, options):
    run(options, anonymized, outdir)
    assert sorted(p.name for p in outdir.iterdir()) == ["audit_summary.json", "restricted"]
    assert sorted(p.name for p in (outdir / "restricted").iterdir()) == [
        "README.txt", "accessions.csv", "dates.csv", "file_audit.jsonl", "leaks.csv",
        "patients.csv", "pixel_redactions.csv", "uids.csv"]


# --------------------------------------------------------------------------
# Mappings
# --------------------------------------------------------------------------

def test_uid_mapping_matches_delivered_files(anonymized, outdir, options):
    run(options, anonymized, outdir)
    fwd = {r["original_uid"]: r["anonymized_uid"] for r in rows(outdir / "restricted/uids.csv")}
    for src in (anonymized / ORIG).rglob("*.dcm"):
        o = pydicom.dcmread(str(src))
        n = pydicom.dcmread(str(anonymized / ANON / src.relative_to(anonymized / ORIG)))
        assert fwd[o.StudyInstanceUID] == n.StudyInstanceUID
        assert fwd[o.SeriesInstanceUID] == n.SeriesInstanceUID
        assert fwd[o.SOPInstanceUID] == n.SOPInstanceUID


def test_identifier_mapping(anonymized, outdir, options):
    run(options, anonymized, outdir)
    pats = {r["original_patient_id"]: r for r in rows(outdir / "restricted/patients.csv")}
    assert set(pats) == {"MRN001", "MRN002"}
    assert pats["MRN001"]["original_patient_name"] == "Doe^Jane"
    assert pats["MRN001"]["n_files"] == "3"
    assert pats["MRN001"]["n_studies"] == "1"
    # dicom-anonymizer's 2023e profile empties PatientID/PatientName
    assert pats["MRN001"]["anonymized_patient_id"] == ""
    accs = {r["original_accession_number"]: r for r in rows(outdir / "restricted/accessions.csv")}
    assert accs["ACC2"]["original_patient_id"] == "MRN002"


def test_date_changes_recorded(anonymized, outdir, options):
    run(options, anonymized, outdir)
    d = rows(outdir / "restricted/dates.csv")
    birth = [r for r in d if r["element"] == "PatientBirthDate"]
    assert {(r["original"], r["new"], r["action"]) for r in birth} == {
        ("19800101", "00010101", "replaced_dummy"), ("19700505", "00010101", "replaced_dummy")}
    assert set(summary(outdir)["dates"]) == {"replaced_dummy"}


def test_emptied_uid_references_reported(anonymized, outdir, options):
    run(options, anonymized, outdir)
    s = summary(outdir)
    assert s["uids"]["references_emptied"]["ReferencedSOPInstanceUID"] == 4
    assert "uid_reference_emptied" in codes(outdir)
    assert s["overall_status"] == "pass"            # warning only


# --------------------------------------------------------------------------
# Per-file change log
# --------------------------------------------------------------------------

def test_per_file_changes_with_before_and_after(anonymized, outdir, options):
    run(options, anonymized, outdir)
    recs = {r["path"]: r for r in read_jsonl(outdir / "restricted/file_audit.jsonl")}
    ch = {c["path"]: c for c in recs["p01/s1/1.dcm"]["changes"]}
    assert ch["PatientName"]["original"] == "Doe^Jane"
    assert ch["PatientName"]["action"] in ("emptied", "replaced")
    assert "new" in ch["PatientName"]
    assert ch["(0009,1010)"]["action"] == "removed"
    assert ch["(0009,1010)"]["original"] == "private note MRN001"
    assert ch["Modality"] == {"path": "Modality", "tag": "(0008,0060)", "keyword": "Modality",
                              "vr": "CS", "action": "retained", "original": "OT", "new": "OT"}
    assert ch["file_meta.MediaStorageSOPInstanceUID"]["action"] == "replaced"
    assert ch["ReferencedImageSequence[0].ReferencedSOPInstanceUID"]["action"] == "emptied"
    assert "PixelData" not in ch


def test_identifying_retained_listed(tmp_path, outdir, options):
    root = tmp_path / "in"
    make_dcm(root / ORIG / "a/1.dcm")
    anonymize_tree(root / ORIG, root / ANON, rules={(0x0008, 0x0080): lambda ds, tag: None})
    options.acknowledgeRetainedTags = "InstitutionName"
    assert run(options, root, outdir) == 0
    rec = read_jsonl(outdir / "restricted/file_audit.jsonl")[0]
    assert rec["identifying_retained"] == ["InstitutionName"]
    assert summary(outdir)["identifying_elements_retained"] == {"InstitutionName": 1}


# --------------------------------------------------------------------------
# PHI hygiene of everything outside restricted/
# --------------------------------------------------------------------------

def _public(outdir, captured):
    return (outdir / "audit_summary.json").read_text() + captured.out + captured.err


def _original_uids(root):
    uids = set()
    for src in (root / ORIG).rglob("*.dcm"):
        ds = pydicom.dcmread(str(src))
        uids |= {ds.StudyInstanceUID, ds.SeriesInstanceUID, ds.SOPInstanceUID}
    return uids


def test_summary_and_logs_are_phi_free(anonymized, outdir, options, capsys):
    run(options, anonymized, outdir)
    public = _public(outdir, capsys.readouterr())
    for needle in (*PHI_STRINGS, "p01/s1", "1.dcm", *_original_uids(anonymized)):
        assert needle not in public


def test_logs_are_phi_free_even_when_leaking(tmp_path, outdir, options, capsys):
    """Leak findings name keywords and hashes, never the leaked value or path."""
    root = tmp_path / "in"
    make_dcm(root / ORIG / "Doe_Jane/1.dcm", description="follow-up DOE knee")
    anonymize_tree(root / ORIG, root / ANON, rules={(0x0008, 0x1030): lambda ds, tag: None})
    assert run(options, root, outdir) == 1
    public = _public(outdir, capsys.readouterr())
    for needle in (*PHI_STRINGS, "DOE", "JANE", "Doe_Jane", *_original_uids(root)):
        assert needle not in public


def test_summary_hashes_restricted_files(anonymized, outdir, options):
    run(options, anonymized, outdir)
    hashes = summary(outdir)["restricted_files_sha256"]
    assert len(hashes) == 8
    for name, h in hashes.items():
        assert hashlib.sha256((outdir / "restricted" / name).read_bytes()).hexdigest() == h


def test_file_index_accounts_for_every_file(anonymized, outdir, options):
    (anonymized / ORIG / "notes.txt").write_text("clinical note")
    run(options, anonymized, outdir)
    s = summary(outdir)
    n_orig = sum(1 for p in (anonymized / ORIG).rglob("*") if p.is_file())
    assert len(s["file_index"]) == s["files"]["total"] == n_orig
    assert len(read_jsonl(outdir / "restricted/file_audit.jsonl")) == n_orig
    audited = [f for f in s["file_index"] if f["status"] == "audited"]
    assert all(len(f["anonymized_sha256"]) == 64 for f in audited)


# --------------------------------------------------------------------------
# Leak scan
# --------------------------------------------------------------------------

@pytest.fixture
def leaky(tmp_path):
    """A study description naming the patient, kept by a custom policy."""
    root = tmp_path / "leaky"
    make_dcm(root / ORIG / "a/1.dcm", description="follow-up DOE knee")
    anonymize_tree(root / ORIG, root / ANON, rules={(0x0008, 0x1030): lambda ds, tag: None})
    return root


def test_header_leak_flagged(leaky, outdir, options):
    assert run(options, leaky, outdir) == 1
    s = summary(outdir)
    assert s["overall_status"] == "fail"
    assert s["leaks"]["header_by_keyword"] == {"StudyDescription": 1}
    leak = rows(outdir / "restricted/leaks.csv")[0]
    assert (leak["location"], leak["source_keyword"], leak["matched"]) == (
        "StudyDescription", "PatientName", "DOE")


def test_without_fail_on_leak_exit_is_zero(leaky, outdir, options):
    options.failOnLeak = False
    assert run(options, leaky, outdir) == 0
    assert summary(outdir)["overall_status"] == "fail"


def test_acknowledged_tag_not_a_leak(leaky, outdir, options):
    options.acknowledgeRetainedTags = "StudyDescription"
    assert run(options, leaky, outdir) == 0
    assert summary(outdir)["leaks"]["header_files"] == 0


def test_retained_uid_is_a_leak(tmp_path, outdir, options):
    root = tmp_path / "in"
    make_dcm(root / ORIG / "a/1.dcm")
    anonymize_tree(root / ORIG, root / ANON, rules={(0x0020, 0x000D): lambda ds, tag: None})
    assert run(options, root, outdir) == 1
    assert "uid_leak" in codes(outdir)
    leak = [r for r in rows(outdir / "restricted/leaks.csv") if r["kind"] == "uid"]
    assert leak[0]["location"] == "StudyInstanceUID"


def test_cross_file_uid_leak(anonymized, outdir, options):
    """File B references file A's ORIGINAL SOPInstanceUID."""
    a = pydicom.dcmread(str(anonymized / ORIG / "p01/s1/1.dcm"))
    rewrite(anonymized / ANON / "p01/s1/2.dcm",
            lambda ds: setattr(ds.ReferencedImageSequence[0], "ReferencedSOPInstanceUID",
                               a.SOPInstanceUID))
    assert run(options, anonymized, outdir) == 1
    leak = [r for r in rows(outdir / "restricted/leaks.csv") if r["kind"] == "uid"]
    assert leak[0]["file"] == "p01/s1/2.dcm"
    assert leak[0]["source_keyword"] == "SOPInstanceUID (another file)"


def test_leak_in_private_tag(tmp_path, outdir, options):
    root = tmp_path / "in"
    make_dcm(root / ORIG / "a/1.dcm")
    anonymize_tree(root / ORIG, root / ANON)
    rewrite(root / ANON / "a/1.dcm", lambda ds: (ds.add_new(0x00110010, "LO", "VENDOR"),
                                               ds.add_new(0x00111001, "LO", "for MRN001")))
    assert run(options, root, outdir) == 1
    assert summary(outdir)["leaks"]["header_by_keyword"] == {"(0011,1001)": 1}


def test_patient_named_folders_leak(tmp_path, outdir, options):
    root = tmp_path / "in"
    make_dcm(root / ORIG / "Doe_Jane/1.dcm")
    anonymize_tree(root / ORIG, root / ANON)
    assert run(options, root, outdir) == 1
    s = summary(outdir)
    assert s["leaks"]["paths"] == 1
    # the anonymizer's own summary repeats the path
    assert s["leaks"]["non_dicom_files"] == 1
    assert {"phi_in_path", "phi_in_non_dicom"} <= codes(outdir)


def test_non_dicom_passthrough_scanned(anonymized, outdir, options):
    (anonymized / ORIG / "p01/report.txt").write_text("Report for Jane Doe, MRN001")
    (anonymized / ANON / "p01/report.txt").write_text("Report for Jane Doe, MRN001")
    assert run(options, anonymized, outdir) == 1
    s = summary(outdir)
    assert s["files"]["by_status"]["non_dicom_copied"] == 1
    assert {"phi_in_non_dicom", "non_dicom_copied"} <= codes(outdir)
    hits = {r["matched"] for r in rows(outdir / "restricted/leaks.csv") if r["file"] == "p01/report.txt"}
    assert {"JANE", "DOE", "MRN001"} <= hits


# --------------------------------------------------------------------------
# Pixels
# --------------------------------------------------------------------------

def test_pixel_mismatch_fails(anonymized, outdir, options):
    rewrite(anonymized / ANON / "p02/s1/1.dcm", lambda ds: setattr(ds, "PixelData", bytes(64)))
    assert run(options, anonymized, outdir) == 1
    assert summary(outdir)["pixels"]["integrity"] == {"match": 3, "mismatch": 1}


def test_skip_pixel_check(anonymized, outdir, options):
    rewrite(anonymized / ANON / "p02/s1/1.dcm", lambda ds: setattr(ds, "PixelData", bytes(64)))
    options.skipPixelCheck = True
    assert run(options, anonymized, outdir) == 0


def test_pixel_redaction_record(anonymized, outdir, options):
    run(options, anonymized, outdir)
    s = summary(outdir)
    assert s["pixels"]["redaction"] == {"no_sidecar": 3, "redacted": 1}
    assert s["pixels"]["entity_types"] == {"DATE_TIME": 1, "PERSON": 1}
    r = {x["file"]: x for x in rows(outdir / "restricted/pixel_redactions.csv")}
    assert r["p01/s1/2.dcm"]["boxes"] == "2"


def test_no_sidecars_no_redaction_noise(tmp_path, outdir, options):
    root = tmp_path / "in"
    make_dcm(root / ORIG / "a/1.dcm")
    anonymize_tree(root / ORIG, root / ANON)
    run(options, root, outdir)
    assert summary(outdir)["pixels"]["redaction"] == {}
    assert "pixel_redaction_unrecorded" not in codes(outdir)


# --------------------------------------------------------------------------
# UID mapping consistency
# --------------------------------------------------------------------------

def test_uid_one_to_many_fails(anonymized, outdir, options):
    rewrite(anonymized / ANON / "p01/s2/1.dcm",
            lambda ds: setattr(ds, "StudyInstanceUID", generate_uid()))
    assert run(options, anonymized, outdir) == 1
    assert summary(outdir)["uids"]["one_to_many"] == 1


def test_uid_many_to_one_fails(anonymized, outdir, options):
    a = pydicom.dcmread(str(anonymized / ANON / "p01/s1/1.dcm"))
    rewrite(anonymized / ANON / "p02/s1/1.dcm",
            lambda ds: setattr(ds, "StudyInstanceUID", a.StudyInstanceUID))
    assert run(options, anonymized, outdir) == 1
    assert summary(outdir)["uids"]["many_to_one"] == 1


# --------------------------------------------------------------------------
# Dates
# --------------------------------------------------------------------------

def _shift(days):
    def fn(ds):
        for kw in ("StudyDate", "PatientBirthDate"):
            d = dt.datetime.strptime(ds.data_element(kw).value, "%Y%m%d").date()
            setattr(ds, kw, (d + dt.timedelta(days=days)).strftime("%Y%m%d"))
    return fn


@pytest.fixture
def shifted(inputdir):
    """Simulate a date-shifting policy: keep dates, then shift per patient."""
    anonymize_tree(inputdir / ORIG, inputdir / ANON,
                   rules={(0x0008, 0x0020): lambda ds, tag: None,
                          (0x0010, 0x0030): lambda ds, tag: None})
    for f in (inputdir / ANON).rglob("*.dcm"):
        rewrite(f, _shift(-100 if "p01" in str(f) else 37))
    return inputdir


def test_consistent_date_shift_recovered(shifted, outdir, options):
    assert run(options, shifted, outdir) == 0
    pats = {r["original_patient_id"]: r for r in rows(outdir / "restricted/patients.csv")}
    assert pats["MRN001"]["date_offset_days"] == "-100"
    assert pats["MRN002"]["date_offset_days"] == "37"


def test_inconsistent_date_shift_warns(shifted, outdir, options):
    rewrite(shifted / ANON / "p01/s2/1.dcm", _shift(5))
    assert run(options, shifted, outdir) == 0
    assert "date_offset_inconsistent" in codes(outdir)


def test_retained_dates_warn(tmp_path, outdir, options):
    root = tmp_path / "in"
    make_dcm(root / ORIG / "a/1.dcm")
    anonymize_tree(root / ORIG, root / ANON, rules={(0x0008, 0x0020): lambda ds, tag: None})
    assert run(options, root, outdir) == 0
    assert "dates_retained" in codes(outdir)
    d = [r for r in rows(outdir / "restricted/dates.csv") if r["element"] == "StudyDate"]
    assert (d[0]["action"], d[0]["delta_days"]) == ("retained", "0")


# --------------------------------------------------------------------------
# Accounting for every file: unmatched, skipped, failed, non-DICOM
# --------------------------------------------------------------------------

def _statuses(outdir):
    return {r["path"]: r["status"] for r in read_jsonl(outdir / "restricted/file_audit.jsonl")}


def test_failed_and_never_seen(inputdir, outdir, options):
    anonymize_tree(inputdir / ORIG, inputdir / ANON, statuses={"p02/s1/1.dcm": "failed"})
    # extension-less DICOM the anonymizer's default **/*.dcm pattern never matches
    make_dcm(inputdir / ORIG / "p02/s1/IM0002", name="Roe^Rick", pid="MRN002")
    assert run(options, inputdir, outdir) == 1
    st = _statuses(outdir)
    assert st["p02/s1/1.dcm"] == "failed_deidentification"
    assert st["p02/s1/IM0002"] == "not_deidentified"
    f = {x["code"]: x for x in summary(outdir)["findings"]}
    assert f["incomplete_pairing"]["by_status"] == {"failed_deidentification": 1,
                                                    "not_deidentified": 1}
    assert summary(outdir)["files"]["pairing_complete"] is False


def test_missing_anonymized(anonymized, outdir, options):
    (anonymized / ANON / "p01/s2/1.dcm").unlink()
    assert run(options, anonymized, outdir) == 1
    assert _statuses(outdir)["p01/s2/1.dcm"] == "missing_anonymized"


def test_unmatched_anonymized(anonymized, outdir, options):
    make_dcm(anonymized / ANON / "stray/9.dcm", name="", pid="", acc="")
    assert run(options, anonymized, outdir) == 1
    assert _statuses(outdir)["stray/9.dcm"] == "unmatched_anonymized"


def test_missing_original(anonymized, outdir, options):
    sp = anonymized / ANON / "deidentification_summary.json"
    s = json.loads(sp.read_text())
    s["files"].append({"path": "gone/1.dcm", "status": "processed"})
    sp.write_text(json.dumps(s))
    assert run(options, anonymized, outdir) == 1
    assert _statuses(outdir)["gone/1.dcm"] == "missing_original"


def test_anonymized_not_dicom(anonymized, outdir, options):
    (anonymized / ANON / "p01/s2/1.dcm").write_text("not dicom")
    assert run(options, anonymized, outdir) == 1
    assert _statuses(outdir)["p01/s2/1.dcm"] == "anonymized_not_dicom"


def test_unreadable_pair(anonymized, outdir, options, capsys):
    (anonymized / ANON / "p01/s2/1.dcm").write_bytes(b"\0" * 128 + b"DICM" + b"junk")
    assert run(options, anonymized, outdir) == 1
    assert _statuses(outdir)["p01/s2/1.dcm"] == "unreadable"


def test_non_dicom_original_not_copied(anonymized, outdir, options):
    (anonymized / ORIG / "p01/notes.txt").write_text("nothing identifying")
    assert run(options, anonymized, outdir) == 0
    assert _statuses(outdir)["p01/notes.txt"] == "not_dicom"
    assert _statuses(outdir)["p01/s1/2.json"] == "redaction_sidecar"


def test_extra_non_dicom_in_anonymized(anonymized, outdir, options):
    (anonymized / ANON / "readme.txt").write_text("nothing identifying")
    assert run(options, anonymized, outdir) == 0
    assert _statuses(outdir)["readme.txt"] == "extra_anonymized_file"


def test_unlisted_in_summary(anonymized, outdir, options):
    sp = anonymized / ANON / "deidentification_summary.json"
    s = json.loads(sp.read_text())
    s["files"] = [f for f in s["files"] if f["path"] != "p02/s1/1.dcm"]
    sp.write_text(json.dumps(s))
    assert run(options, anonymized, outdir) == 0
    assert "unlisted_in_anonymizer_summary" in codes(outdir)


def test_pairs_by_path_without_anonymizer_summary(inputdir, outdir, options):
    """Another tool's output: no summary, explicit directories."""
    anonymize_tree(inputdir / ORIG, inputdir / ANON, summary=False)
    (inputdir / ANON / "p02/s1/1.dcm").unlink()
    options.originalDir, options.anonymizedDir = ORIG, ANON
    assert run(options, inputdir, outdir) == 1
    s = summary(outdir)
    assert s["files"]["by_status"]["audited"] == 3
    assert s["files"]["by_status"]["not_deidentified"] == 1
    assert s["anonymizer"]["summary_found"] is False


def test_nothing_audited_never_passes(inputdir, outdir, options):
    """Pointing --anonymizedDir at an unanonymized copy must not PASS."""
    (inputdir / "copy").mkdir()
    options.originalDir, options.anonymizedDir = ORIG, "copy"
    assert run(options, inputdir, outdir) == 1
    assert {"nothing_audited", "incomplete_pairing"} <= codes(outdir)


# --------------------------------------------------------------------------
# Input layout
# --------------------------------------------------------------------------

def test_explicit_directories(anonymized, outdir, options):
    (anonymized / "something_else").mkdir()
    options.originalDir, options.anonymizedDir = ORIG, ANON
    assert run(options, anonymized, outdir) == 0


@pytest.mark.parametrize("setup", ["ambiguous", "no_summary", "ungrouped"])
def test_bad_layout_exits_2(inputdir, tmp_path, outdir, options, setup):
    root = inputdir
    if setup == "ambiguous":
        anonymize_tree(inputdir / ORIG, inputdir / ANON)
        (inputdir / "something_else").mkdir()
    elif setup == "ungrouped":
        root = tmp_path / "flat"
        root.mkdir()
        (root / "deidentification_summary.json").write_text(json.dumps({"files": []}))
    assert run(options, root, outdir) == 2
