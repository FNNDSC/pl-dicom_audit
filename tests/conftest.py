"""
Fixtures build the same layout ChRIS produces when pl-topologicalcopy
(--groupByInstance) joins the pixel-redaction and header-anonymization
nodes:

    inputdir/
        pl-dicom_pixel_redact_1/   identified headers, scrubbed pixels
        pl-dicom_anonymize_2/      de-identified tree + deidentification_summary.json

The de-identified tree is produced with the real dicom-anonymizer engine at
the same pin pl-dicom_anonymize uses, and a summary in that plugin's format.
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

IDENT = "pl-dicom_pixel_redact_1"
ANON = "pl-dicom_anonymize_2"


def make_dcm(path: Path, *, name, pid, acc, study, series, birth="19800101",
             study_date="20240301", description="MR brain"):
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
    ds.StudyInstanceUID = study
    ds.SeriesInstanceUID = series
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


def anonymize_tree(ident: Path, anon: Path, rules=None, statuses=None):
    """
    De-identify every .dcm under ident into anon (same relative paths) and
    write a pl-dicom_anonymize style deidentification_summary.json.
    statuses: {relpath: "failed"} to simulate per-file anonymizer failures.
    """
    statuses = statuses or {}
    records = []
    for src in sorted(ident.rglob("*.dcm")):
        rel = str(src.relative_to(ident))
        status = statuses.get(rel, "processed")
        if status == "processed":
            dst = anon / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            anonymize_dicom_file(str(src), str(dst), rules or {}, True)
        records.append({"path": rel, "path_hash": "x", "status": status})
    anon.mkdir(parents=True, exist_ok=True)
    (anon / "deidentification_summary.json").write_text(json.dumps({
        "plugin_version": "1.2.0",
        "upstream_dicom_anonymizer_version": "1.0.13.post1",
        "keep_private_tags": False,
        "output_verification_enabled": True,
        "overall_status": "failed" if "failed" in statuses.values() else "success",
        "files": records,
    }))


@pytest.fixture
def inputdir(tmp_path):
    root = tmp_path / "input"
    ident = root / IDENT
    study = generate_uid()
    s1, s2 = generate_uid(), generate_uid()
    common = dict(name="Doe^Jane", pid="MRN001", acc="ACC1", study=study)
    make_dcm(ident / "Doe_Jane/s1/1.dcm", series=s1, **common)
    make_dcm(ident / "Doe_Jane/s1/2.dcm", series=s1, **common)
    make_dcm(ident / "Doe_Jane/s2/1.dcm", series=s2, **common)
    make_dcm(ident / "Roe_Rick/s1/1.dcm", name="Roe^Rick", pid="MRN002", acc="ACC2",
             study=generate_uid(), series=generate_uid(), birth="19700505",
             study_date="20240410")
    # pl-dicom_pixel_redact --save-bboxes sidecar for one file
    (ident / "Doe_Jane/s1/2.json").write_text(json.dumps([
        {"entity_type": "PERSON", "score": 0.85, "left": 1, "top": 1, "width": 4, "height": 2},
        {"entity_type": "DATE_TIME", "score": 0.6, "left": 1, "top": 5, "width": 4, "height": 2},
    ]))
    return root


@pytest.fixture
def outdir(tmp_path):
    d = tmp_path / "output"
    d.mkdir()
    return d


@pytest.fixture
def options():
    return Namespace(
        identifiedDir="",
        anonymizedDir="",
        acknowledgeRetainedTags="",
        residualMinLength=3,
        skipPixelCheck=False,
        reportOnly=False,
    )


def read_jsonl(path: Path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def summary(outdir: Path) -> dict:
    return json.loads((outdir / "audit_summary.json").read_text())


def rewrite(path: Path, fn):
    ds = pydicom.dcmread(str(path))
    fn(ds)
    ds.save_as(str(path), write_like_original=False)
