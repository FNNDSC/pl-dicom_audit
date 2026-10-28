"""
End-to-end tests: run the real pl-dicom_anonymize CLI (pinned in the `dev`
extra) and then the dicom_audit CLI as subprocesses, laid out the way
pl-topologicalcopy --groupByInstance joins two ChRIS nodes.

These are skipped when dicom_anonymize is not installed, except when the
environment variable CI is set, where a missing anonymizer is a failure (CI
must never silently skip the e2e suite).
"""

import csv
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import ANON, ORIG, PHI_STRINGS, make_dcm

BIN = Path(sys.executable).parent
ENV = {**os.environ, "PATH": f"{BIN}{os.pathsep}{os.environ.get('PATH', '')}"}


def _which(cmd):
    return shutil.which(cmd, path=ENV["PATH"])


if not _which("dicom_anonymize"):
    if os.environ.get("CI"):
        pytest.fail("dicom_anonymize is not installed; install the plugin with the 'dev' extra",
                    pytrace=False)
    pytestmark = pytest.mark.skip(reason="pl-dicom_anonymize not installed (pip install '.[dev]')")


def sh(*args):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True, env=ENV,
                          timeout=300)


def anonymize(root: Path, *flags):
    """Run pl-dicom_anonymize on root/ORIG into root/ANON."""
    return sh("dicom_anonymize", *flags, root / ORIG, root / ANON)


def audit(root: Path, out: Path, *flags):
    return sh("dicom_audit", *flags, root, out)


def summary(out: Path):
    return json.loads((out / "audit_summary.json").read_text())


def codes(out: Path):
    return {f["code"] for f in summary(out)["findings"]}


def rows(path):
    with open(path, newline="") as fh:
        return list(csv.DictReader(fh))


@pytest.fixture
def raw(tmp_path):
    root = tmp_path / "join"
    make_dcm(root / ORIG / "p01/s1/1.dcm")
    make_dcm(root / ORIG / "p01/s1/2.dcm")
    make_dcm(root / ORIG / "p02/s1/1.dcm", name="Roe^Rick", pid="MRN002", acc="ACC2",
             birth="19700505", study_date="20240410")
    return root


@pytest.fixture
def out(tmp_path):
    return tmp_path / "audit"


def test_clean_pipeline(raw, out):
    a = anonymize(raw)
    assert a.returncode == 0, a.stderr
    r = audit(raw, out, "--failOnLeak")
    assert r.returncode == 0, r.stderr
    s = summary(out)
    assert s["overall_status"] == "pass"
    assert s["files"]["by_status"] == {"audited": 3}
    assert s["anonymizer"]["plugin_version"] == "1.2.0"
    pats = {p["original_patient_id"] for p in rows(out / "restricted/patients.csv")}
    assert pats == {"MRN001", "MRN002"}
    # make_dcm gives each file its own study and series: 3 studies + 3 series + 3 SOPs
    assert len(rows(out / "restricted/uids.csv")) == 9


def test_job_log_is_phi_free(raw, out):
    anonymize(raw)
    r = audit(raw, out, "--failOnLeak")
    log = r.stdout + r.stderr
    for needle in (*PHI_STRINGS, "p01", "1.dcm"):
        assert needle not in log
    assert "file#1 (" in r.stderr                      # path hashes only


def test_policy_leak_fails_only_with_flag(raw, out, tmp_path):
    make_dcm(raw / ORIG / "p03/s1/1.dcm", name="Poe^Ann", pid="MRN003",
             description="follow-up POE shoulder")
    a = anonymize(raw, "--dictionary", '{"StudyDescription": "keep"}')
    assert a.returncode == 0, a.stderr               # the anonymizer's own check passes
    r = audit(raw, out, "--failOnLeak")
    assert r.returncode == 1
    assert "residual_phi" in codes(out)
    assert "POE" not in r.stderr + r.stdout
    r2 = audit(raw, tmp_path / "audit2")
    assert r2.returncode == 0
    assert summary(tmp_path / "audit2")["overall_status"] == "fail"


def test_acknowledged_tags_pass_through(raw, out):
    anonymize(raw, "--dictionary", '{"InstitutionName": "keep"}',
              "--acknowledgeRetainedTags", "InstitutionName")
    r = audit(raw, out, "--failOnLeak", "--acknowledgeRetainedTags", "InstitutionName")
    assert r.returncode == 0, r.stderr
    assert summary(out)["identifying_elements_retained"] == {"InstitutionName": 3}


def test_anonymizer_stops_early_is_incomplete_pairing(raw, out):
    (raw / ORIG / "p01/s1/15_broken.dcm").write_bytes(b"\0" * 128 + b"DICM" + b"garbage")
    a = anonymize(raw)                                # no --continueOnError: stops at failure
    assert a.returncode == 1
    r = audit(raw, out, "--failOnLeak")
    assert r.returncode == 1
    s = summary(out)
    assert s["anonymizer"]["stopped_early"] is True
    pairing = {f["code"]: f for f in s["findings"]}["incomplete_pairing"]["by_status"]
    assert pairing["failed_deidentification"] == 1
    assert pairing.get("not_deidentified", 0) >= 1   # files after the failure were never seen
    assert s["files"]["total"] == 4                   # every original file accounted for


def test_copied_non_dicom_scanned(raw, out):
    (raw / ORIG / "p01/report.txt").write_text("Discharge summary: Jane Doe (MRN001)")
    anonymize(raw, "--pattern", "**/*", "--copyNonDicom")
    r = audit(raw, out, "--failOnLeak")
    assert r.returncode == 1
    assert {"phi_in_non_dicom", "non_dicom_copied"} <= codes(out)


def test_patient_named_folders_leak(tmp_path, out):
    root = tmp_path / "join"
    make_dcm(root / ORIG / "Doe_Jane/1.dcm")
    anonymize(root)
    r = audit(root, out, "--failOnLeak")
    assert r.returncode == 1
    assert "phi_in_path" in codes(out)


def test_bad_layout_exits_2(raw, out):
    r = audit(raw, out)                               # no anonymized tree yet
    assert r.returncode == 2
    assert "FATAL" in r.stderr


def test_chris_descriptor(tmp_path):
    if not _which("chris_plugin_info"):
        pytest.skip("chris_plugin_info not on PATH")
    r = subprocess.run(["chris_plugin_info", "--dock-image", "docker.io/fnndsc/pl-dicom_audit:test",
                        "dicom_audit"],
                       capture_output=True, text=True, env=ENV, cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    d = json.loads(r.stdout)
    assert d["type"] == "ds"
    params = {p["flag"]: p for p in d["parameters"]}
    assert params["--failOnLeak"]["type"] == "bool"
    assert params["--failOnLeak"]["default"] is False
    assert {"--originalDir", "--anonymizedDir", "--acknowledgeRetainedTags",
            "--residualMinLength", "--skipPixelCheck"} <= set(params)


def test_invalid_values_never_reach_the_log(tmp_path, out):
    """
    pydicom validates lazily and its warnings quote the offending value. An
    invalid UID that spells a name must not appear in the audit's job log.
    The bytes are patched directly so pydicom cannot validate on write.
    """
    import pydicom
    root = tmp_path / "join"
    f = make_dcm(root / ORIG / "p01/1.dcm")
    raw = f.read_bytes()
    uid = pydicom.dcmread(str(f)).StudyInstanceUID.encode()
    bad = (b"1.2.Doe.Jane." + b"0" * 64)[:len(uid)]
    f.write_bytes(raw.replace(uid, bad))
    anonymize(root)
    r = audit(root, out)
    log = r.stdout + r.stderr
    assert "Doe" not in log and "Invalid value" not in log and "Warning" not in log
