import csv
import datetime as dt
import hashlib
import json

import pydicom
import pytest
from pydicom.uid import generate_uid

from conftest import ANON, IDENT, anonymize_tree, make_dcm, read_jsonl, rewrite, summary
from dicom_audit import main

PHI_STRINGS = ("Doe", "Jane", "Roe", "Rick", "MRN001", "MRN002", "ACC1", "ACC2",
               "19800101", "19700505", "20240301", "General Hospital", "Smith")


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
# Clean pipeline
# --------------------------------------------------------------------------

def test_clean_pipeline_passes(inputdir, outdir, options):
    anonymize_tree(inputdir / IDENT, inputdir / ANON)
    assert run(options, inputdir, outdir) == 0
    s = summary(outdir)
    assert s["overall_status"] == "pass"
    assert s["files"]["by_status"] == {"audited": 4}
    assert s["patients"]["count"] == 2
    assert s["accessions"] == 2
    assert s["uids"]["by_level"] == {"series": 3, "sop": 4, "study": 2}
    assert s["uids"]["one_to_many"] == s["uids"]["many_to_one"] == 0
    assert s["pixels"]["integrity"] == {"match": 4}
    assert s["anonymizer"]["overall_status"] == "success"


def test_uid_crosswalk_matches_delivered_files(inputdir, outdir, options):
    anonymize_tree(inputdir / IDENT, inputdir / ANON)
    run(options, inputdir, outdir)
    fwd = {r["original_uid"]: r["deidentified_uid"] for r in rows(outdir / "restricted/uids.csv")}
    for src in (inputdir / IDENT).rglob("*.dcm"):
        o = pydicom.dcmread(str(src))
        n = pydicom.dcmread(str(inputdir / ANON / src.relative_to(inputdir / IDENT)))
        assert fwd[o.SOPInstanceUID] == n.SOPInstanceUID
        assert fwd[o.SeriesInstanceUID] == n.SeriesInstanceUID
        assert fwd[o.StudyInstanceUID] == n.StudyInstanceUID


def test_emptied_uid_references_are_reported(inputdir, outdir, options):
    # The PS3.15 2023e profile in dicom-anonymizer empties the UIDs inside
    # ReferencedImageSequence instead of remapping them.
    anonymize_tree(inputdir / IDENT, inputdir / ANON)
    run(options, inputdir, outdir)
    s = summary(outdir)
    assert s["uids"]["references_emptied"]["ReferencedSOPInstanceUID"] == 4
    assert any(f["code"] == "uid_reference_emptied" and f["severity"] == "warning"
               for f in s["findings"])


def test_patient_and_accession_crosswalks(inputdir, outdir, options):
    anonymize_tree(inputdir / IDENT, inputdir / ANON)
    run(options, inputdir, outdir)
    pats = {r["original_patient_id"]: r for r in rows(outdir / "restricted/patients.csv")}
    assert set(pats) == {"MRN001", "MRN002"}
    assert pats["MRN001"]["original_patient_name"] == "Doe^Jane"
    assert pats["MRN001"]["n_files"] == "3"
    assert pats["MRN001"]["n_studies"] == "1"
    accs = {r["original_accession_number"]: r for r in rows(outdir / "restricted/accessions.csv")}
    assert set(accs) == {"ACC1", "ACC2"}
    assert accs["ACC1"]["original_patient_id"] == "MRN001"


def test_per_file_log_records_every_change(inputdir, outdir, options):
    anonymize_tree(inputdir / IDENT, inputdir / ANON)
    run(options, inputdir, outdir)
    recs = {r["path"]: r for r in read_jsonl(outdir / "restricted/file_audit.jsonl")}
    assert len(recs) == 4
    changes = {c["path"]: c for c in recs["Doe_Jane/s1/1.dcm"]["changes"]}
    assert changes["PatientName"]["original"] == "Doe^Jane"
    assert changes["PatientName"]["action"] in ("emptied", "replaced")
    assert changes["(0009,1010)"]["action"] == "removed"          # private tag stripped
    assert changes["ReferencedImageSequence[0].ReferencedSOPInstanceUID"]["action"] == "emptied"
    assert changes["file_meta.MediaStorageSOPInstanceUID"]["action"] == "replaced"
    assert "PixelData" not in changes


# --------------------------------------------------------------------------
# PHI hygiene of everything outside restricted/
# --------------------------------------------------------------------------

def test_summary_and_logs_are_phi_free(inputdir, outdir, options, capsys):
    anonymize_tree(inputdir / IDENT, inputdir / ANON)
    run(options, inputdir, outdir)
    captured = capsys.readouterr()
    public = (outdir / "audit_summary.json").read_text() + captured.out + captured.err
    original_uids = set()
    for src in (inputdir / IDENT).rglob("*.dcm"):
        ds = pydicom.dcmread(str(src))
        original_uids |= {ds.StudyInstanceUID, ds.SeriesInstanceUID, ds.SOPInstanceUID}
    for needle in (*PHI_STRINGS, "Doe_Jane", "s1/1.dcm", *original_uids):
        assert needle not in public
    assert sorted(p.name for p in outdir.iterdir()) == ["audit_summary.json", "restricted"]


def test_summary_hashes_restricted_files(inputdir, outdir, options):
    anonymize_tree(inputdir / IDENT, inputdir / ANON)
    run(options, inputdir, outdir)
    hashes = summary(outdir)["restricted_files_sha256"]
    assert set(hashes) == {"README.txt", "patients.csv", "accessions.csv", "uids.csv",
                           "dates.csv", "pixel_redactions.csv", "file_audit.jsonl"}
    for name, h in hashes.items():
        assert hashlib.sha256((outdir / "restricted" / name).read_bytes()).hexdigest() == h


# --------------------------------------------------------------------------
# Residual PHI
# --------------------------------------------------------------------------

@pytest.fixture
def leaky_inputdir(tmp_path):
    """A study description naming the patient, kept by a custom policy."""
    root = tmp_path / "leaky"
    make_dcm(root / IDENT / "a/1.dcm", name="Doe^Jane", pid="MRN001", acc="ACC1",
             study=generate_uid(), series=generate_uid(), description="follow-up DOE knee")
    anonymize_tree(root / IDENT, root / ANON, rules={(0x0008, 0x1030): lambda ds, tag: None})
    return root


def test_residual_phi_fails_the_audit(leaky_inputdir, outdir, options):
    assert run(options, leaky_inputdir, outdir) == 1
    s = summary(outdir)
    assert s["overall_status"] == "fail"
    assert s["residual_phi"]["by_keyword"] == {"StudyDescription": 1}
    assert any(f["code"] == "residual_phi" for f in s["findings"])
    rec = read_jsonl(outdir / "restricted/file_audit.jsonl")[0]
    assert rec["residual_phi"][0]["source_keyword"] == "PatientName"
    assert rec["residual_phi"][0]["matched"] == "DOE"


def test_acknowledged_tag_is_not_residual(leaky_inputdir, outdir, options):
    options.acknowledgeRetainedTags = "StudyDescription"
    assert run(options, leaky_inputdir, outdir) == 0
    assert summary(outdir)["residual_phi"]["files"] == 0


def test_report_only_never_exits_nonzero(leaky_inputdir, outdir, options):
    options.reportOnly = True
    assert run(options, leaky_inputdir, outdir) == 0
    assert summary(outdir)["overall_status"] == "fail"


# --------------------------------------------------------------------------
# Pixels
# --------------------------------------------------------------------------

def test_pixel_mismatch_fails(inputdir, outdir, options):
    anonymize_tree(inputdir / IDENT, inputdir / ANON)
    rewrite(inputdir / ANON / "Roe_Rick/s1/1.dcm", lambda ds: setattr(ds, "PixelData", bytes(64)))
    assert run(options, inputdir, outdir) == 1
    s = summary(outdir)
    assert s["pixels"]["integrity"] == {"match": 3, "mismatch": 1}
    assert len(s["pixels"]["mismatch_file_hashes"]) == 1


def test_skip_pixel_check(inputdir, outdir, options):
    anonymize_tree(inputdir / IDENT, inputdir / ANON)
    rewrite(inputdir / ANON / "Roe_Rick/s1/1.dcm", lambda ds: setattr(ds, "PixelData", bytes(64)))
    options.skipPixelCheck = True
    assert run(options, inputdir, outdir) == 0
    assert summary(outdir)["pixels"]["integrity"] == {}


def test_pixel_redaction_record(inputdir, outdir, options):
    anonymize_tree(inputdir / IDENT, inputdir / ANON)
    run(options, inputdir, outdir)
    s = summary(outdir)
    assert s["pixels"]["redaction"] == {"no_sidecar": 3, "redacted": 1}
    assert s["pixels"]["entity_types"] == {"DATE_TIME": 1, "PERSON": 1}
    r = {x["file"]: x for x in rows(outdir / "restricted/pixel_redactions.csv")}
    assert r["Doe_Jane/s1/2.dcm"]["boxes"] == "2"
    assert r["Doe_Jane/s1/2.dcm"]["max_score"] == "0.85"
    assert any(f["code"] == "pixel_redaction_unrecorded" for f in s["findings"])


# --------------------------------------------------------------------------
# UIDs
# --------------------------------------------------------------------------

def test_uid_one_to_many_fails(inputdir, outdir, options):
    anonymize_tree(inputdir / IDENT, inputdir / ANON)
    rewrite(inputdir / ANON / "Doe_Jane/s2/1.dcm",
            lambda ds: setattr(ds, "StudyInstanceUID", generate_uid()))
    assert run(options, inputdir, outdir) == 1
    assert summary(outdir)["uids"]["one_to_many"] == 1


def test_uid_many_to_one_fails(inputdir, outdir, options):
    anonymize_tree(inputdir / IDENT, inputdir / ANON)
    a = pydicom.dcmread(str(inputdir / ANON / "Doe_Jane/s1/1.dcm"))
    rewrite(inputdir / ANON / "Roe_Rick/s1/1.dcm",
            lambda ds: setattr(ds, "StudyInstanceUID", a.StudyInstanceUID))
    assert run(options, inputdir, outdir) == 1
    assert summary(outdir)["uids"]["many_to_one"] == 1


# --------------------------------------------------------------------------
# Dates
# --------------------------------------------------------------------------

def test_dummy_dates_classified(inputdir, outdir, options):
    anonymize_tree(inputdir / IDENT, inputdir / ANON)
    run(options, inputdir, outdir)
    s = summary(outdir)
    assert set(s["dates"]) == {"replaced_dummy"}
    pats = {r["original_patient_id"]: r for r in rows(outdir / "restricted/patients.csv")}
    assert pats["MRN001"]["date_offset_days"] == ""
    assert pats["MRN001"]["date_handling"].startswith("replaced_dummy=")


def _shift(days):
    def fn(ds):
        for kw in ("StudyDate", "PatientBirthDate"):
            d = dt.datetime.strptime(ds.data_element(kw).value, "%Y%m%d").date()
            setattr(ds, kw, (d + dt.timedelta(days=days)).strftime("%Y%m%d"))
    return fn


@pytest.fixture
def shifted(inputdir):
    """Simulate a date-shifting header stage: copy identified dates, shift them."""
    anonymize_tree(inputdir / IDENT, inputdir / ANON,
                   rules={(0x0008, 0x0020): lambda ds, tag: None,
                          (0x0010, 0x0030): lambda ds, tag: None})
    for f in (inputdir / ANON).rglob("*.dcm"):
        rewrite(f, _shift(-100 if "Doe_Jane" in str(f) else 37))
    return inputdir


def test_consistent_date_shift_recovered(shifted, outdir, options):
    assert run(options, shifted, outdir) == 0
    pats = {r["original_patient_id"]: r for r in rows(outdir / "restricted/patients.csv")}
    assert pats["MRN001"]["date_offset_days"] == "-100"
    assert pats["MRN002"]["date_offset_days"] == "37"
    assert pats["MRN001"]["date_offset_consistent"] == "True"
    d = [r for r in rows(outdir / "restricted/dates.csv") if r["element"] == "PatientBirthDate"]
    assert {r["delta_days"] for r in d} == {"-100", "37"}


def test_inconsistent_date_shift_warns(shifted, outdir, options):
    rewrite(shifted / ANON / "Doe_Jane/s2/1.dcm", _shift(5))
    assert run(options, shifted, outdir) == 0       # warning, not an error
    s = summary(outdir)
    assert any(f["code"] == "date_offset_inconsistent" for f in s["findings"])
    pats = {r["original_patient_id"]: r for r in rows(outdir / "restricted/patients.csv")}
    assert pats["MRN001"]["date_offset_consistent"] == "False"


# --------------------------------------------------------------------------
# Coverage accounting
# --------------------------------------------------------------------------

def test_failed_and_unseen_files_are_accounted(inputdir, outdir, options):
    anonymize_tree(inputdir / IDENT, inputdir / ANON, statuses={"Roe_Rick/s1/1.dcm": "failed"})
    # an extension-less DICOM the anonymizer's default **/*.dcm pattern never matched
    make_dcm(inputdir / IDENT / "Roe_Rick/s1/IM0002", name="Roe^Rick", pid="MRN002",
             acc="ACC2", study=generate_uid(), series=generate_uid())
    assert run(options, inputdir, outdir) == 0
    s = summary(outdir)
    assert s["files"]["by_status"] == {"audited": 3, "failed_deidentification": 1,
                                       "not_deidentified": 1}
    codes = {f["code"] for f in s["findings"]}
    assert {"deidentification_failed", "not_deidentified"} <= codes


def test_missing_deidentified_file_fails(inputdir, outdir, options):
    anonymize_tree(inputdir / IDENT, inputdir / ANON)
    (inputdir / ANON / "Doe_Jane/s2/1.dcm").unlink()
    assert run(options, inputdir, outdir) == 1
    assert summary(outdir)["files"]["by_status"]["missing_deidentified"] == 1


def test_unreadable_file_fails_without_leaking(inputdir, outdir, options, capsys):
    anonymize_tree(inputdir / IDENT, inputdir / ANON)
    (inputdir / ANON / "Doe_Jane/s2/1.dcm").write_bytes(b"\0" * 128 + b"DICM" + b"junk")
    assert run(options, inputdir, outdir) == 1
    err = capsys.readouterr().err
    assert "Doe" not in err and "MRN" not in err


# --------------------------------------------------------------------------
# Input layout
# --------------------------------------------------------------------------

def test_explicit_directories(inputdir, outdir, options):
    anonymize_tree(inputdir / IDENT, inputdir / ANON)
    (inputdir / "something_else").mkdir()           # breaks auto-detection
    options.identifiedDir, options.anonymizedDir = IDENT, ANON
    assert run(options, inputdir, outdir) == 0


def test_ambiguous_layout_exits_2(inputdir, outdir, options):
    anonymize_tree(inputdir / IDENT, inputdir / ANON)
    (inputdir / "something_else").mkdir()
    assert run(options, inputdir, outdir) == 2


def test_missing_summary_exits_2(inputdir, outdir, options):
    assert run(options, inputdir, outdir) == 2


def test_ungrouped_join_exits_2(tmp_path, outdir, options):
    flat = tmp_path / "flat"
    flat.mkdir()
    (flat / "deidentification_summary.json").write_text(json.dumps({"files": []}))
    assert run(options, flat, outdir) == 2
