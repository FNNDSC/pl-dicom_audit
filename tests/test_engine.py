"""Unit tests: audit_engine functions and the CLI's pure helpers."""

import hashlib
import json
from pathlib import Path

import pytest
from pydicom.dataset import Dataset
from pydicom.sequence import Sequence
from pydicom.uid import generate_uid

from audit_engine import (
    Change,
    Crosswalk,
    MalformedDicomError,
    NeedleIndex,
    classify_date,
    diff_datasets,
    diff_file,
    find_residual_phi,
    find_residual_phi_in_file,
    token_in,
    is_dicom_file,
    phi_needles,
    pixel_integrity,
    read_dicom,
    read_redaction_sidecar,
    relpath_hash,
    render,
    sanitize_exception,
    uid_needles,
)
from conftest import make_dcm
from dicom_audit import Entry, LayoutError, classify, collect_ui_values, locate_trees


def ds_with(**kw):
    ds = Dataset()
    for k, v in kw.items():
        setattr(ds, k, v)
    return ds


def by_path(changes):
    return {c.path: c for c in changes}


# --------------------------------------------------------------------------
# render / helpers
# --------------------------------------------------------------------------

def test_render_text_multivalue_and_binary():
    ds = ds_with(PatientName="Doe^Jane", ImageType=["ORIGINAL", "PRIMARY"])
    ds.add_new(0x00091001, "OB", b"\x01\x02\x03")
    assert render(ds["PatientName"]) == "Doe^Jane"
    assert render(ds["ImageType"]) == ["ORIGINAL", "PRIMARY"]
    assert render(ds[0x00091001]) == {"sha256": hashlib.sha256(b"\x01\x02\x03").hexdigest(),
                                      "length": 3}


def test_relpath_hash_matches_pl_dicom_anonymize():
    # same formula as pl-dicom_anonymize's safety.relpath_hash
    assert relpath_hash(Path("a/b.dcm")) == hashlib.sha256(b"a/b.dcm").hexdigest()[:12]


def test_sanitize_exception_never_quotes_message():
    cls, msg = sanitize_exception(ValueError("Doe^Jane is not a valid date"))
    assert cls == "ValueError" and "Doe" not in msg
    cls, msg = sanitize_exception(RuntimeError("MRN001"))
    assert "MRN001" not in msg


def test_is_dicom_and_strict_read(tmp_path):
    good = make_dcm(tmp_path / "good.dcm")
    junk = tmp_path / "junk.dcm"
    junk.write_bytes(b"\0" * 128 + b"DICM" + b"garbage")
    text = tmp_path / "t.txt"
    text.write_text("hello")
    assert is_dicom_file(good) and is_dicom_file(junk) and not is_dicom_file(text)
    assert read_dicom(good).PatientID == "MRN001"
    with pytest.raises(MalformedDicomError):
        read_dicom(junk)


# --------------------------------------------------------------------------
# diff
# --------------------------------------------------------------------------

def test_diff_actions():
    o = ds_with(PatientName="Doe^Jane", PatientID="MRN001", AccessionNumber="ACC1",
                Modality="MR", StudyDescription="")
    n = ds_with(PatientName="ANON", PatientID="", Modality="MR", StudyDescription="",
                PatientSex="O")
    ch = by_path(diff_datasets(o, n))
    assert (ch["PatientName"].action, ch["PatientName"].original, ch["PatientName"].new) == (
        "replaced", "Doe^Jane", "ANON")
    assert ch["PatientID"].action == "emptied"
    assert (ch["AccessionNumber"].action, ch["AccessionNumber"].original) == ("removed", "ACC1")
    assert ch["PatientSex"].action == "added"
    assert (ch["Modality"].action, ch["Modality"].new) == ("retained", "MR")
    assert "StudyDescription" not in ch          # empty and unchanged: nothing to record


def test_diff_recurses_sequences_and_counts_items():
    o = Dataset()
    o.ReferencedImageSequence = Sequence([ds_with(ReferencedSOPInstanceUID="1.2.3"),
                                          ds_with(ReferencedSOPInstanceUID="1.2.4")])
    n = Dataset()
    n.ReferencedImageSequence = Sequence([ds_with(ReferencedSOPInstanceUID="9.9.9")])
    ch = by_path(diff_datasets(o, n))
    c = ch["ReferencedImageSequence[0].ReferencedSOPInstanceUID"]
    assert (c.action, c.original, c.new) == ("replaced", "1.2.3", "9.9.9")
    assert (ch["ReferencedImageSequence"].action, ch["ReferencedImageSequence"].original,
            ch["ReferencedImageSequence"].new) == ("items_removed", 2, 1)


def test_diff_skips_pixel_data_and_includes_file_meta(tmp_path):
    a = read_dicom(make_dcm(tmp_path / "a.dcm"))
    b = read_dicom(make_dcm(tmp_path / "b.dcm"))
    b.PixelData = bytes(64)
    ch = by_path(diff_file(a, b))
    assert "PixelData" not in ch
    assert ch["file_meta.MediaStorageSOPInstanceUID"].action == "replaced"


def test_change_as_dict_omits_absent_values():
    d = Change("X", "(0008,0050)", "AccessionNumber", "SH", "removed", original="A").as_dict()
    assert d == {"path": "X", "tag": "(0008,0050)", "keyword": "AccessionNumber", "vr": "SH",
                 "action": "removed", "original": "A"}


# --------------------------------------------------------------------------
# dates
# --------------------------------------------------------------------------

@pytest.mark.parametrize("vr,action,orig,new,expected", [
    ("DA", "replaced", "20240301", "00010101", ("replaced_dummy", None)),
    ("TM", "replaced", "101500", "000000.00", ("replaced_dummy", None)),
    ("DA", "replaced", "20240301", "20231123", ("shifted", -99)),
    ("DT", "replaced", "20240301101500", "20240311101500", ("shifted", 10)),
    ("TM", "replaced", "101500", "120000", ("replaced", None)),
    ("DA", "retained", "20240301", "20240301", ("retained", 0)),
    ("DA", "emptied", "20240301", "", ("emptied", None)),
    ("DA", "removed", "20240301", None, ("removed", None)),
])
def test_classify_date(vr, action, orig, new, expected):
    assert classify_date(Change("StudyDate", "t", "StudyDate", vr, action, orig, new)) == expected


# --------------------------------------------------------------------------
# leak scan
# --------------------------------------------------------------------------

def test_phi_needles_split_names_and_respect_min_length():
    ds = ds_with(PatientName="Doe^Jane^Q", PatientID="AB", PatientBirthDate="19800101")
    n = phi_needles(ds, 3)
    assert {"DOE^JANE^Q", "DOE", "JANE", "19800101"} <= set(n)
    assert "Q" not in n and "AB" not in n
    assert n["DOE"] == "PatientName"


def test_uid_needles_include_file_meta(tmp_path):
    ds = read_dicom(make_dcm(tmp_path / "a.dcm"))
    n = uid_needles(ds)
    assert n[ds.StudyInstanceUID] == "StudyInstanceUID"
    assert ds.file_meta.MediaStorageSOPInstanceUID in n
    assert ds.SOPClassUID not in n                 # class UIDs are not identifying


def test_find_residual_text_case_insensitive_and_nested():
    deid = Dataset()
    deid.StudyDescription = "follow-up for doe"
    deid.RequestAttributesSequence = Sequence([ds_with(RequestedProcedureDescription="MRN001 knee")])
    hits = find_residual_phi(deid, {"DOE": "PatientName", "MRN001": "PatientID"}, frozenset())
    assert {(h["path"], h["matched"]) for h in hits} == {
        ("StudyDescription", "DOE"),
        ("RequestAttributesSequence[0].RequestedProcedureDescription", "MRN001")}


def test_find_residual_acknowledged_skipped():
    deid = ds_with(InstitutionName="General Hospital")
    assert find_residual_phi(deid, {"GENERAL HOSPITAL": "InstitutionName"},
                             frozenset({"InstitutionName"})) == []


def test_find_residual_uid_exact_and_in_text():
    uid = generate_uid()
    deid = ds_with(StudyInstanceUID=uid, StudyComments=f"see {uid}")
    hits = find_residual_phi(deid, {}, frozenset(), uids={uid: "StudyInstanceUID"})
    assert {(h["path"], h["kind"]) for h in hits} == {("StudyInstanceUID", "uid"),
                                                      ("StudyComments", "uid")}


def test_find_residual_scans_un_private_bytes_not_pixels():
    deid = Dataset()
    deid.add_new(0x00111001, "UN", b"note about MRN001")
    deid.add_new(0x7FE00010, "OB", b"MRN001")         # PixelData never searched
    hits = find_residual_phi(deid, {"MRN001": "PatientID"}, frozenset())
    assert [h["path"] for h in hits] == ["(0011,1001)"]


def test_find_residual_in_file_scans_file_meta(tmp_path):
    ident = read_dicom(make_dcm(tmp_path / "a.dcm"))
    deid = read_dicom(make_dcm(tmp_path / "b.dcm", name="", pid="", acc="",
                               birth="", private=False))
    deid.file_meta.MediaStorageSOPInstanceUID = ident.SOPInstanceUID
    hits = find_residual_phi_in_file(deid, ident, 3, frozenset())
    assert any(h["path"] == "file_meta.MediaStorageSOPInstanceUID" for h in hits)


def test_numeric_values_must_stand_alone():
    hits = lambda text: find_residual_phi(ds_with(StudyComments=text), {"1234": "AccessionNumber"},
                                          frozenset())
    assert hits("accession 1234 reviewed")
    assert hits("ACC-1234")
    assert not hits("ref a01234ff")                   # inside a hex string
    assert not hits("12345")                          # inside a longer number
    idx = NeedleIndex()
    idx.add({"1234": "AccessionNumber", "DOE": "PatientName"})
    assert idx.search('"path_hash": "9a1234bc"') == []
    assert idx.search("scans/1234/doejane.dcm") == [("1234", "AccessionNumber"),
                                                    ("DOE", "PatientName")]


def test_token_in():
    assert token_in("DOE", "DOEJANE") and token_in("19800101", "BORN 19800101")
    assert not token_in("19800101", "X198001012")


def test_needle_index():
    idx = NeedleIndex()
    assert idx.search("anything") == []
    idx.add({"DOE": "PatientName", "MRN001": "PatientID"})
    idx.add({"DOE": "OtherPatientNames"})            # first source wins
    assert sorted(idx.search("Doe_Jane/mrn001/doe.dcm")) == [("DOE", "PatientName"),
                                                             ("MRN001", "PatientID")]
    assert idx.search("nothing here") == []


# --------------------------------------------------------------------------
# pixels
# --------------------------------------------------------------------------

def test_pixel_integrity():
    a, b = Dataset(), Dataset()
    assert pixel_integrity(a, b) == "absent_both"
    a.PixelData = b"\x01"
    assert pixel_integrity(a, b) == "absent_in_deidentified"
    b.PixelData = b"\x01"
    assert pixel_integrity(a, b) == "match"
    b.PixelData = b"\x02"
    assert pixel_integrity(a, b) == "mismatch"


def test_read_redaction_sidecar(tmp_path):
    dcm = tmp_path / "1.dcm"
    assert read_redaction_sidecar(dcm)["status"] == "no_sidecar"
    (tmp_path / "1.json").write_text("[]")
    assert read_redaction_sidecar(dcm)["status"] == "no_detections"
    (tmp_path / "1.json").write_text(json.dumps([{"entity_type": "PERSON", "score": 0.7}]))
    r = read_redaction_sidecar(dcm)
    assert (r["status"], r["boxes"], r["entity_types"], r["max_score"]) == (
        "redacted", 1, {"PERSON": 1}, 0.7)
    (tmp_path / "1.json").write_text("{not json")
    assert read_redaction_sidecar(dcm)["status"] == "unreadable_sidecar"


# --------------------------------------------------------------------------
# crosswalk
# --------------------------------------------------------------------------

def _uid_change(kw, o, n, action="replaced"):
    return Change(kw, "t", kw, "UI", action, o, n)


def test_crosswalk_uid_conflicts_and_broken_references():
    x = Crosswalk()
    o = ds_with(PatientID="P1")
    x.add_file("a", o, Dataset(), [_uid_change("StudyInstanceUID", "1.1", "9.1"),
                                   _uid_change("ReferencedSOPInstanceUID", "1.5", "", "emptied")])
    x.add_file("b", o, Dataset(), [_uid_change("StudyInstanceUID", "1.1", "9.2"),
                                   _uid_change("SeriesInstanceUID", "1.3", "9.1")])
    assert x.uid_conflicts() == (["1.1"], ["9.1"])
    assert x.broken_references == {"ReferencedSOPInstanceUID": 1}


def test_crosswalk_pseudonyms():
    x = Crosswalk()
    x.add_file("a", ds_with(PatientID="P1"), ds_with(PatientID="X1"), [])
    x.add_file("b", ds_with(PatientID="P1"), ds_with(PatientID="X2"), [])
    x.add_file("c", ds_with(PatientID="P2"), ds_with(PatientID="X2"), [])
    assert x.pseudonym_findings() == (["P1"], ["X2"])


def test_crosswalk_patient_key_without_id():
    assert Crosswalk.patient_key(ds_with(PatientName="Doe^Jane")) == \
        "<no PatientID; name=Doe^Jane>"


def test_crosswalk_date_offsets():
    x = Crosswalk()
    p = ds_with(PatientID="P1")
    d = lambda o, n: Change("StudyDate", "t", "StudyDate", "DA", "replaced", o, n)
    x.add_file("a", p, Dataset(), [d("20240301", "20240201")])
    assert x.patient_date_handling(x.patients["P1"])[1:] == (-29, True)
    x.add_file("b", p, Dataset(), [d("20240301", "20240202")])
    assert x.patient_date_handling(x.patients["P1"])[1:] == (None, False)


# --------------------------------------------------------------------------
# CLI helpers: classification and layout
# --------------------------------------------------------------------------

@pytest.mark.parametrize("orig,anon,anon_status,expected", [
    ("dicom", "dicom", "processed", "pair"),
    ("dicom", "dicom", None, "pair"),
    ("dicom", None, "failed", "failed_deidentification"),
    ("dicom", None, "processed", "missing_anonymized"),
    ("dicom", None, None, "not_deidentified"),
    ("dicom", "other", "processed", "anonymized_not_dicom"),
    ("other", None, "skipped_not_dicom", "not_dicom"),
    ("other", "other", "copied_non_dicom", "non_dicom_copied"),
    ("other", "dicom", None, "unmatched_anonymized"),
    (None, "dicom", None, "unmatched_anonymized"),
    (None, "other", None, "extra_anonymized_file"),
    (None, None, "processed", "missing_original"),
])
def test_classify(orig, anon, anon_status, expected):
    assert classify(Entry("x/1.dcm", orig, anon, anon_status), set()) == expected


def test_classify_sidecar():
    assert classify(Entry("x/1.json", "other", None, None), {"x/1.json"}) == "redaction_sidecar"


def test_collect_ui_values_recurses(tmp_path):
    ds = read_dicom(make_dcm(tmp_path / "a.dcm"))
    paths = dict(collect_ui_values(ds))
    assert paths["StudyInstanceUID"] == ds.StudyInstanceUID
    assert paths["ReferencedImageSequence[0].ReferencedSOPInstanceUID"] == ds.SOPInstanceUID


def test_locate_trees(tmp_path):
    (tmp_path / "orig").mkdir()
    (tmp_path / "anon").mkdir()
    (tmp_path / "anon/deidentification_summary.json").write_text("{}")
    assert locate_trees(tmp_path, "", "") == ((tmp_path / "orig").resolve(),
                                              (tmp_path / "anon").resolve())
    with pytest.raises(LayoutError):
        locate_trees(tmp_path, "anon", "anon")
    with pytest.raises(LayoutError):
        locate_trees(tmp_path, "orig", "missing")
