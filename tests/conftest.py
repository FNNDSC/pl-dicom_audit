"""
Shared fixtures.

Trees use the layout ChRIS produces when pl-topologicalcopy (--groupByInstance)
joins the original and the pl-dicom_anonymize nodes:

    inputdir/
        pl-dircopy_1/              original DICOMs
        pl-dicom_anonymize_2/      anonymized tree + deidentification_summary.json

Integration tests build the anonymized tree in-process with the real
dicom-anonymizer engine (same pin as pl-dicom_anonymize) and a summary in that
plugin's format. End-to-end tests (test_e2e.py) run the real plugins instead.

Directory names are deliberately free of PHI (p01, p02): pl-dicom_anonymize
copies paths verbatim, so patient-named folders are themselves a leak, which
has its own tests.
"""

import json
from argparse import Namespace
from pathlib import Path

import pydicom
import pytest
from dicomanonymizer.simpledicomanonymizer import anonymize_dicom_file
from pydicom.dataset import Dataset, FileDataset, FileMetaDataset
from pydicom.sequence import Sequence
from pydicom.uid import ExplicitVRLittleEndian, generate_uid

ORIG = "pl-dircopy_1"
ANON = "pl-dicom_anonymize_2"

#: Every identifying value the fixtures put into headers.
PHI_STRINGS = ("Doe", "Jane", "Roe", "Rick", "MRN001", "MRN002", "ACC1", "ACC2",
               "19800101", "19700505", "20240301", "20240410", "General Hospital",
               "Smith", "Robert")


def make_dcm(path: Path, *, name="Doe^Jane", pid="MRN001", acc="ACC1", study=None,
             series=None, birth="19800101", study_date="20240301",
             description="MR brain", private=True):
    path.parent.mkdir(parents=True, exist_ok=True)
    meta = FileMetaDataset()
    meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.7"
    meta.MediaStorageSOPInstanceUID = generate_uid()
    meta.TransferSyntaxUID = ExplicitVRLittleEndian
    ds = FileDataset(str(path), {}, file_meta=meta, preamble=b"\0" * 128)
    ds.PatientName = name
    ds.PatientID = pid
    ds.PatientBirthDate = birth
    ds.AccessionNumber = acc
    ds.StudyDate = study_date
    ds.StudyTime = "101500"
    ds.StudyInstanceUID = study or generate_uid()
    ds.SeriesInstanceUID = series or generate_uid()
    ds.SOPInstanceUID = meta.MediaStorageSOPInstanceUID
    ds.SOPClassUID = meta.MediaStorageSOPClassUID
    ds.InstitutionName = "General Hospital"
    ds.ReferringPhysicianName = "Smith^Robert"
    ds.StudyDescription = description
    ds.Modality = "OT"
    ref = Dataset()
    ref.ReferencedSOPClassUID = meta.MediaStorageSOPClassUID
    ref.ReferencedSOPInstanceUID = ds.SOPInstanceUID
    ds.ReferencedImageSequence = Sequence([ref])
    if private:
        ds.add_new(0x00090010, "LO", "ACME")
        ds.add_new(0x00091010, "LO", f"private note {pid}")
    ds.Rows = ds.Columns = 8
    ds.BitsAllocated = ds.BitsStored = 8
    ds.HighBit = 7
    ds.PixelRepresentation = 0
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.PixelData = bytes(range(64))
    ds.is_little_endian = True
    ds.is_implicit_VR = False
    ds.save_as(str(path), write_like_original=False)
    return path


def anonymize_tree(orig: Path, anon: Path, rules=None, statuses=None, summary=True):
    """
    Anonymize every .dcm under orig into anon (same relative paths) and,
    unless summary=False, write a pl-dicom_anonymize style
    deidentification_summary.json. statuses: {relpath: "failed"} simulates
    per-file anonymizer failures (no output written, as the plugin does).
    """
    statuses = statuses or {}
    records = []
    for src in sorted(orig.rglob("*.dcm")):
        rel = str(src.relative_to(orig))
        status = statuses.get(rel, "processed")
        if status == "processed":
            dst = anon / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            anonymize_dicom_file(str(src), str(dst), rules or {}, True)
        records.append({"path": rel, "path_hash": "x", "status": status})
    anon.mkdir(parents=True, exist_ok=True)
    if summary:
        (anon / "deidentification_summary.json").write_text(json.dumps({
            "plugin_version": "1.2.0",
            "upstream_dicom_anonymizer_version": "1.0.13.post1",
            "keep_private_tags": False,
            "copy_non_dicom": False,
            "output_verification_enabled": True,
            "stopped_early": False,
            "overall_status": "failed" if "failed" in statuses.values() else "success",
            "files": records,
        }))


@pytest.fixture
def inputdir(tmp_path):
    """Two patients, one with two series; one pixel-redaction sidecar."""
    root = tmp_path / "input"
    orig = root / ORIG
    study = generate_uid()
    s1, s2 = generate_uid(), generate_uid()
    make_dcm(orig / "p01/s1/1.dcm", study=study, series=s1)
    make_dcm(orig / "p01/s1/2.dcm", study=study, series=s1)
    make_dcm(orig / "p01/s2/1.dcm", study=study, series=s2)
    make_dcm(orig / "p02/s1/1.dcm", name="Roe^Rick", pid="MRN002", acc="ACC2",
             birth="19700505", study_date="20240410")
    # pl-dicom_pixel_redact --save-bboxes sidecar for one file
    (orig / "p01/s1/2.json").write_text(json.dumps([
        {"entity_type": "PERSON", "score": 0.85, "left": 1, "top": 1, "width": 4, "height": 2},
        {"entity_type": "DATE_TIME", "score": 0.6, "left": 1, "top": 5, "width": 4, "height": 2},
    ]))
    return root


@pytest.fixture
def anonymized(inputdir):
    """inputdir with a clean anonymized tree next to the original."""
    anonymize_tree(inputdir / ORIG, inputdir / ANON)
    return inputdir


@pytest.fixture
def outdir(tmp_path):
    d = tmp_path / "output"
    d.mkdir()
    return d


@pytest.fixture
def options():
    return Namespace(
        originalDir="",
        anonymizedDir="",
        acknowledgeRetainedTags="",
        residualMinLength=3,
        skipPixelCheck=False,
        failOnLeak=True,
    )


def read_jsonl(path: Path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def summary(outdir: Path) -> dict:
    return json.loads((outdir / "audit_summary.json").read_text())


def rewrite(path: Path, fn):
    ds = pydicom.dcmread(str(path))
    fn(ds)
    ds.save_as(str(path), write_like_original=False)


def codes(outdir: Path) -> set:
    return {f["code"] for f in summary(outdir)["findings"]}
