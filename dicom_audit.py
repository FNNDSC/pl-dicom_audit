#!/usr/bin/env python
"""
pl-dicom_audit: build a de-identification audit by diffing the identified
DICOM tree (pl-dicom_pixel_redact output: clean pixels, original headers)
against the de-identified tree (pl-dicom_anonymize output).

Output layout (outputdir):

    audit_summary.json        PHI-free: counts, checks, findings, file hashes
    restricted/               PHI: crosswalks and the per-file change log
        README.txt
        patients.csv
        accessions.csv
        uids.csv
        dates.csv
        pixel_redactions.csv
        file_audit.jsonl

stdout/stderr never contain PHI or relative paths (hashes only).
"""


import csv
import hashlib
import json
import sys
import time
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser, Namespace
from collections import Counter
from pathlib import Path

import pydicom
from chris_plugin import chris_plugin

from audit_engine import (
    Crosswalk,
    diff_file,
    find_residual_phi,
    is_dicom_file,
    phi_needles,
    pixel_integrity,
    read_dicom,
    read_redaction_sidecar,
    relpath_hash,
    sanitize_exception,
)

__version__ = '0.1.0'

ANONYMIZER_SUMMARY = "deidentification_summary.json"

DISPLAY_TITLE = r"""
       _           _ _                                  _ _ _
      | |         | (_)                                | (_) |
 _ __ | |______ __| |_  ___ ___  _ __ ___   __ _ _   _  __| |_| |_
| '_ \| |______/ _` | |/ __/ _ \| '_ ` _ \ / _` | | | |/ _` | | __|
| |_) | |     | (_| | | (_| (_) | | | | | | (_| | |_| | (_| | | |_
| .__/|_|      \__,_|_|\___\___/|_| |_| |_|\__,_|\__,_|\__,_|_|\__|
| |                                 ______
|_|                                |______|
"""

parser = ArgumentParser(
    description=(
        "Audit DICOM de-identification: diff identified headers against "
        "de-identified headers and emit crosswalk tables, a per-file change "
        "log, and a PHI-free summary."
    ),
    formatter_class=ArgumentDefaultsHelpFormatter,
)
parser.add_argument('-V', '--version', action='version', version=f'%(prog)s {__version__}')
parser.add_argument(
    '--identifiedDir', default='', metavar='SUBDIR',
    help=(
        "Subdirectory of inputdir holding the identified tree (pl-dicom_pixel_redact "
        "output). Default: auto-detect -- the one top-level subdirectory that does "
        "not contain the de-identified tree."
    ),
)
parser.add_argument(
    '--anonymizedDir', default='', metavar='SUBDIR',
    help=(
        "Subdirectory of inputdir holding the de-identified tree (pl-dicom_anonymize "
        f"output). Default: auto-detect -- the directory containing {ANONYMIZER_SUMMARY}."
    ),
)
parser.add_argument(
    '--acknowledgeRetainedTags', default='', metavar='TAG[,TAG...]',
    help=(
        "Comma-separated DICOM keywords intentionally kept by the anonymization "
        "policy; the residual-PHI scan ignores matches inside these elements. Use "
        "the same value given to pl-dicom_anonymize."
    ),
)
parser.add_argument(
    '--residualMinLength', type=int, default=3,
    help="Minimum length of an identifying token searched for by the residual-PHI scan.",
)
parser.add_argument(
    '--skipPixelCheck', action='store_true', default=False,
    help=(
        "Do not compare PixelData between the trees. By default the plugin confirms "
        "the header stage left the redacted pixels byte-identical."
    ),
)
parser.add_argument(
    '--reportOnly', action='store_true', default=False,
    help=(
        "Always exit 0 once the audit is written. By default the plugin exits 1 on "
        "residual PHI, UID mapping conflicts, pixel mismatches, or unreadable/missing "
        "pairs, so a pipeline stops on an audit failure."
    ),
)


# --------------------------------------------------------------------------
# Locating the two trees
# --------------------------------------------------------------------------

class LayoutError(Exception):
    pass


def locate_trees(inputdir: Path, identified_opt: str, anonymized_opt: str) -> tuple[Path, Path]:
    if anonymized_opt:
        anon = (inputdir / anonymized_opt).resolve()
    else:
        found = sorted(p.parent for p in inputdir.rglob(ANONYMIZER_SUMMARY))
        if len(found) != 1:
            raise LayoutError(
                f"expected exactly one {ANONYMIZER_SUMMARY} under inputdir to locate the "
                f"de-identified tree, found {len(found)}; pass --anonymizedDir"
            )
        anon = found[0].resolve()

    root = inputdir.resolve()
    if anon == root:
        raise LayoutError(
            "the de-identified tree is inputdir itself, so the identified tree cannot "
            "be separated from it. Join the two parent nodes with pl-topologicalcopy "
            "using --groupByInstance so each lands in its own subdirectory."
        )

    if identified_opt:
        ident = (inputdir / identified_opt).resolve()
    else:
        candidates = [
            d.resolve() for d in sorted(inputdir.iterdir())
            if d.is_dir() and d.resolve() != anon and d.resolve() not in anon.parents
        ]
        if len(candidates) != 1:
            raise LayoutError(
                f"expected exactly one top-level subdirectory besides the de-identified "
                f"tree, found {len(candidates)}; pass --identifiedDir"
            )
        ident = candidates[0]

    for label, d in (("identified", ident), ("de-identified", anon)):
        if not d.is_dir():
            raise LayoutError(f"{label} tree directory does not exist")
    if ident == anon or ident in anon.parents or anon in ident.parents:
        raise LayoutError("identified and de-identified trees must not overlap")
    return ident, anon


# --------------------------------------------------------------------------
# Work list
# --------------------------------------------------------------------------

def build_worklist(ident: Path, anon: Path) -> tuple[list[tuple[str, str]], dict]:
    """
    Return ([(relpath, anonymizer_status)], anonymizer_summary_or_empty).

    The anonymizer's own summary is authoritative for which files it
    attempted. Identified DICOMs it never saw, and de-identified DICOMs it
    does not list, are added as their own categories so nothing is silently
    left out of the audit.
    """
    summary_path = anon / ANONYMIZER_SUMMARY
    summary: dict = {}
    work: dict[str, str] = {}
    if summary_path.is_file():
        summary = json.loads(summary_path.read_text())
        for rec in summary.get("files", []):
            work[str(rec["path"])] = str(rec.get("status", "unknown"))

    for f in sorted(p for p in ident.rglob("*") if p.is_file()):
        rel = str(f.relative_to(ident))
        if rel not in work and is_dicom_file(f):
            work[rel] = "not_seen_by_anonymizer"

    for f in sorted(p for p in anon.rglob("*") if p.is_file()):
        rel = str(f.relative_to(anon))
        if rel in work or not is_dicom_file(f):
            continue
        # With no anonymizer summary (e.g. --anonymizedDir pointing at a tree
        # from another tool) every de-identified DICOM is treated as processed.
        work[rel] = "processed" if not summary else "unlisted_in_anonymizer_summary"

    return sorted(work.items()), summary


# --------------------------------------------------------------------------
# Per-file audit
# --------------------------------------------------------------------------

def audit_one(rel: str, anon_status: str, ident: Path, anon: Path, xwalk: Crosswalk,
              options: Namespace) -> dict:
    ip, ap = ident / rel, anon / rel
    rec: dict = {"path": rel, "path_hash": relpath_hash(rel), "anonymizer_status": anon_status}

    if anon_status in ("skipped_not_dicom", "copied_non_dicom"):
        rec["status"] = "not_dicom"
        return rec
    if anon_status == "failed":
        rec["status"] = "failed_deidentification"
        rec["pixel_redaction"] = read_redaction_sidecar(ip) if ip.is_file() else None
        return rec
    if anon_status == "not_seen_by_anonymizer":
        rec["status"] = "not_deidentified"
        return rec
    if not ip.is_file():
        rec["status"] = "missing_identified"
        return rec
    if not ap.is_file():
        rec["status"] = "missing_deidentified"
        return rec

    try:
        ids = read_dicom(ip)
        dds = read_dicom(ap)
    except Exception as e:  # noqa: BLE001
        cls, summary = sanitize_exception(e)
        rec.update(status="error", error_class=cls, error_summary=summary)
        return rec

    try:
        changes = diff_file(ids, dds)
        residual = find_residual_phi(
            dds, phi_needles(ids, options.residualMinLength), options.acknowledged_tags_set
        )
        xwalk.add_file(rel, ids, dds, changes)
    except Exception as e:  # noqa: BLE001
        cls, summary = sanitize_exception(e)
        rec.update(status="error", error_class=cls, error_summary=summary)
        return rec
    rec.update(
        status="audited" if anon_status == "processed" else anon_status,
        patient_key=xwalk.patient_key(ids),
        changes=[c.as_dict() for c in changes],
        action_counts=dict(Counter(c.action for c in changes)),
        residual_phi=residual,
        pixel_integrity=None if options.skipPixelCheck else pixel_integrity(ids, dds),
        pixel_redaction=read_redaction_sidecar(ip),
    )
    return rec


# --------------------------------------------------------------------------
# Writers
# --------------------------------------------------------------------------

RESTRICTED_README = """\
THIS DIRECTORY CONTAINS PROTECTED HEALTH INFORMATION.

It holds the re-identification key for a de-identified DICOM dataset:
original patient names and IDs, accession numbers, UIDs and dates, mapped
to their de-identified values. Anyone with this directory and the
de-identified dataset can re-identify every patient.

Store it under the same (or stricter) access controls as the original,
identified data, and never alongside the de-identified dataset.

Files:
  patients.csv          original -> de-identified patient identity, date handling
  accessions.csv        original -> de-identified accession numbers
  uids.csv              original -> de-identified Study/Series/SOP/FoR UIDs
  dates.csv             every date/time element: original, new, action, offset
  pixel_redactions.csv  pixel-stage redaction record per file
  file_audit.jsonl      one JSON record per file: every header change
"""


def write_csv(path: Path, rows, fieldnames: list[str]) -> int:
    n = 0
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        for row in rows:
            w.writerow(row)
            n += 1
    return n


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

@chris_plugin(
    parser=parser,
    title='DICOM de-identification audit',
    category='DICOM De-identification',
    min_memory_limit='500Mi',
    min_cpu_limit='1000m',
    min_gpu_limit=0,
)
def main(options: Namespace, inputdir: Path, outputdir: Path):
    print(DISPLAY_TITLE)
    started = time.time()
    options.acknowledged_tags_set = frozenset(
        t.strip() for t in options.acknowledgeRetainedTags.split(",") if t.strip()
    )
    if options.residualMinLength < 1:
        parser.error("--residualMinLength must be at least 1")

    try:
        ident, anon = locate_trees(inputdir, options.identifiedDir, options.anonymizedDir)
        worklist, anon_summary = build_worklist(ident, anon)
    except LayoutError as e:
        print(f"FATAL: {e}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:  # noqa: BLE001
        cls, summary = sanitize_exception(e)
        print(f"FATAL: could not read input layout ({cls}): {summary}", file=sys.stderr)
        sys.exit(2)

    restricted = outputdir / "restricted"
    restricted.mkdir(parents=True, exist_ok=True)
    (restricted / "README.txt").write_text(RESTRICTED_README)

    xwalk = Crosswalk()
    status_counts: Counter = Counter()
    action_counts: Counter = Counter()
    pixel_counts: Counter = Counter()
    redaction_counts: Counter = Counter()
    entity_counts: Counter = Counter()
    residual_by_keyword: Counter = Counter()
    residual_files: list[str] = []
    pixel_mismatch_files: list[str] = []
    error_files: list[str] = []
    total_boxes = 0
    redaction_rows: list[dict] = []

    with open(restricted / "file_audit.jsonl", "w") as log:
        for i, (rel, anon_status) in enumerate(worklist, 1):
            rec = audit_one(rel, anon_status, ident, anon, xwalk, options)
            log.write(json.dumps(rec, default=str) + "\n")
            h, st = rec["path_hash"], rec["status"]
            status_counts[st] += 1
            action_counts.update(rec.get("action_counts", {}))

            if st in ("error", "missing_deidentified", "missing_identified"):
                error_files.append(h)
            pi = rec.get("pixel_integrity")
            if pi:
                pixel_counts[pi] += 1
                if pi == "mismatch":
                    pixel_mismatch_files.append(h)
            pr = rec.get("pixel_redaction")
            if pr:
                redaction_counts[pr["status"]] += 1
                entity_counts.update(pr.get("entity_types", {}))
                total_boxes += pr.get("boxes", 0)
                redaction_rows.append({
                    "file": rel, "status": pr["status"], "boxes": pr.get("boxes", 0),
                    "entity_types": ";".join(f"{k}={v}" for k, v in pr.get("entity_types", {}).items()),
                    "min_score": pr.get("min_score", ""), "max_score": pr.get("max_score", ""),
                    "pixel_integrity": rec.get("pixel_integrity") or "",
                })
            if rec.get("residual_phi"):
                residual_files.append(h)
                residual_by_keyword.update(hit["keyword"] for hit in rec["residual_phi"])

            flag = {
                "audited": "OK   ", "not_dicom": "SKIP ", "not_deidentified": "WARN ",
                "failed_deidentification": "WARN ",
            }.get(st, "FAIL ")
            extra = ""
            if rec.get("residual_phi"):
                flag, extra = "FAIL ", f" residual PHI in {len(rec['residual_phi'])} element(s)"
            elif pi == "mismatch":
                flag, extra = "FAIL ", " PixelData differs between trees"
            print(f"[{flag}] file#{i} ({h}): {st}{extra}", file=sys.stderr)

    # -- crosswalk tables ----------------------------------------------------
    n_patients = write_csv(restricted / "patients.csv", xwalk.rows_patients(), [
        "original_patient_id", "original_patient_name", "deidentified_patient_id",
        "deidentified_patient_name", "pseudonym_consistent", "date_handling",
        "date_offset_days", "date_offset_consistent", "n_studies", "n_files"])
    n_acc = write_csv(restricted / "accessions.csv", xwalk.rows_accessions(), [
        "original_accession_number", "deidentified_accession_number",
        "original_patient_id", "original_study_instance_uid", "consistent"])
    uid_rows = list(xwalk.rows_uids())
    write_csv(restricted / "uids.csv", uid_rows, [
        "level", "original_uid", "deidentified_uid", "occurrences", "consistent"])
    write_csv(restricted / "dates.csv", xwalk.dates, [
        "patient_key", "file", "element", "vr", "original", "new", "action", "delta_days"])
    write_csv(restricted / "pixel_redactions.csv", redaction_rows, [
        "file", "status", "boxes", "entity_types", "min_score", "max_score", "pixel_integrity"])

    # -- findings ------------------------------------------------------------
    uid_one_to_many, uid_many_to_one = xwalk.uid_conflicts()
    pseudo_inconsistent, pseudo_collisions = xwalk.pseudonym_findings()
    offsets = [xwalk.patient_date_handling(p) for p in xwalk.patients.values()]
    inconsistent_offsets = sum(1 for _, _, ok in offsets if not ok)

    findings = []

    def finding(code, severity, count, message):
        if count:
            findings.append({"code": code, "severity": severity, "count": count, "message": message})

    finding("residual_phi", "error", len(residual_files),
            "de-identified headers still contain values from the identified headers")
    finding("pixel_mismatch", "error", len(pixel_mismatch_files),
            "PixelData changed between the pixel-scrubbed and de-identified files")
    finding("uid_one_to_many", "error", len(uid_one_to_many),
            "an original UID was mapped to more than one new UID")
    finding("uid_many_to_one", "error", len(uid_many_to_one),
            "different original UIDs were mapped to the same new UID")
    finding("unpaired_or_unreadable", "error", len(error_files),
            "files listed as processed could not be paired or read")
    finding("deidentification_failed", "warning", status_counts["failed_deidentification"],
            "the anonymizer reported failures; those files are absent from the de-identified tree")
    finding("not_deidentified", "warning", status_counts["not_deidentified"],
            "identified DICOM files the anonymizer never examined (check its --pattern)")
    finding("unlisted_deidentified", "warning", status_counts["unlisted_in_anonymizer_summary"],
            "de-identified DICOM files not listed in the anonymizer summary")
    finding("pseudonym_inconsistent", "warning", len(pseudo_inconsistent),
            "a patient received more than one de-identified PatientID")
    finding("pseudonym_collision", "warning", len(pseudo_collisions),
            "different patients share one non-empty de-identified PatientID")
    finding("uid_reference_emptied", "warning", sum(xwalk.broken_references.values()),
            "UID references (Referenced*UID) were emptied or removed rather than remapped, "
            "so those cross-object links no longer resolve")
    finding("date_offset_inconsistent", "warning", inconsistent_offsets,
            "a patient's dates were shifted by more than one offset")
    finding("pixel_redaction_unrecorded", "info", redaction_counts["no_sidecar"],
            "no bounding-box sidecar; run pl-dicom_pixel_redact with --save-bboxes to record redactions")

    failed = any(f["severity"] == "error" for f in findings)

    restricted_hashes = {
        p.name: file_sha256(p) for p in sorted(restricted.iterdir()) if p.is_file()
    }
    uid_levels = Counter(r["level"] for r in uid_rows)
    summary = {
        "plugin": "pl-dicom_audit",
        "plugin_version": __version__,
        "pydicom_version": pydicom.__version__,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "elapsed_seconds": round(time.time() - started, 3),
        "anonymizer": {
            "summary_found": bool(anon_summary),
            "plugin_version": anon_summary.get("plugin_version"),
            "upstream_version": anon_summary.get("upstream_dicom_anonymizer_version"),
            "overall_status": anon_summary.get("overall_status"),
            "keep_private_tags": anon_summary.get("keep_private_tags"),
            "output_verification_enabled": anon_summary.get("output_verification_enabled"),
        },
        "options": {
            "acknowledged_retained_tags": sorted(options.acknowledged_tags_set),
            "residual_min_length": options.residualMinLength,
            "pixel_check": not options.skipPixelCheck,
            "report_only": bool(options.reportOnly),
        },
        "files": {"total": len(worklist), "by_status": dict(sorted(status_counts.items()))},
        "header_changes": dict(sorted(action_counts.items())),
        "patients": {
            "count": n_patients,
            "pseudonym_inconsistent": len(pseudo_inconsistent),
            "pseudonym_collisions": len(pseudo_collisions),
            "date_offset_consistent": n_patients - inconsistent_offsets,
        },
        "accessions": n_acc,
        "uids": {
            "mapped": len(uid_rows),
            "by_level": dict(sorted(uid_levels.items())),
            "references_emptied": dict(sorted(xwalk.broken_references.items())),
            "one_to_many": len(uid_one_to_many),
            "many_to_one": len(uid_many_to_one),
        },
        "dates": dict(sorted(xwalk.date_actions.items())),
        "residual_phi": {
            "files": len(residual_files),
            "by_keyword": dict(sorted(residual_by_keyword.items())),
            "file_hashes": residual_files,
        },
        "pixels": {
            "integrity": dict(sorted(pixel_counts.items())),
            "mismatch_file_hashes": pixel_mismatch_files,
            "redaction": dict(sorted(redaction_counts.items())),
            "boxes": total_boxes,
            "entity_types": dict(sorted(entity_counts.items())),
        },
        "findings": findings,
        "overall_status": "fail" if failed else "pass",
        "restricted_files_sha256": restricted_hashes,
    }
    (outputdir / "audit_summary.json").write_text(json.dumps(summary, indent=2))

    print("---", file=sys.stderr)
    print(f"files={len(worklist)} " + " ".join(f"{k}={v}" for k, v in sorted(status_counts.items())),
          file=sys.stderr)
    print(f"patients={n_patients} accessions={n_acc} uids={len(uid_rows)}", file=sys.stderr)
    for f in findings:
        print(f"{f['severity'].upper()}: {f['code']} ({f['count']}): {f['message']}", file=sys.stderr)
    print(f"Audit {summary['overall_status'].upper()}. PHI-bearing tables are in restricted/.",
          file=sys.stderr)

    if failed and not options.reportOnly:
        sys.exit(1)


if __name__ == '__main__':
    main()
