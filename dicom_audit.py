#!/usr/bin/env python
"""
pl-dicom_audit: an audit record of what pl-dicom_anonymize changed.

pl-dicom_anonymize writes only a status summary; it keeps no record of the
old-to-new identifiers, UIDs or dates. This plugin pairs every original
DICOM with its anonymized counterpart (same relative path), compares the
two headers with pydicom, scans the anonymized output for leaked original
values, and writes the result, stored separately from the de-identified
data.

Output layout (outputdir):

    audit_summary.json        no PHI: counts, findings, path hashes, file hashes
    restricted/               PHI: crosswalks, leaks and the per-file change log
        README.txt
        patients.csv
        accessions.csv
        uids.csv
        dates.csv
        leaks.csv
        pixel_redactions.csv
        file_audit.jsonl

stdout/stderr never contain PHI, identifiers or relative paths: only counts,
finding codes and 12-character path hashes.
"""

import csv
import hashlib
import json
import sys
import time
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser, Namespace
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pydicom
from chris_plugin import chris_plugin

from audit_engine import (
    WATCHED_KEYWORDS,
    Crosswalk,
    UID_NEEDLE_KEYWORDS,
    NeedleIndex,
    diff_file,
    find_residual_phi_in_file,
    is_dicom_file,
    phi_needles,
    pixel_integrity,
    read_dicom,
    read_redaction_sidecar,
    relpath_hash,
    sanitize_exception,
    uid_needles,
)

__version__ = '0.2.0'

ANONYMIZER_SUMMARY = "deidentification_summary.json"

#: Non-DICOM files in the anonymized tree larger than this are scanned only
#: up to this many bytes (and flagged as partially scanned).
NON_DICOM_SCAN_LIMIT = 64 * 1024 * 1024

#: Source keywords that mark a needle as an original instance UID.
UID_SOURCES = frozenset(UID_NEEDLE_KEYWORDS) | {"MediaStorageSOPInstanceUID"}

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
        "Audit what pl-dicom_anonymize changed: pair each original DICOM with "
        "its anonymized counterpart, record every header change and the "
        "identifier, UID and date mappings, and scan the anonymized output "
        "for leaked original values."
    ),
    formatter_class=ArgumentDefaultsHelpFormatter,
)
parser.add_argument('-V', '--version', action='version', version=f'%(prog)s {__version__}')
parser.add_argument(
    '--originalDir', default='', metavar='SUBDIR',
    help=(
        "Subdirectory of inputdir holding the original (pre-anonymization) tree. "
        "Default: auto-detect -- the one top-level subdirectory that is not the "
        "anonymized tree."
    ),
)
parser.add_argument(
    '--anonymizedDir', default='', metavar='SUBDIR',
    help=(
        "Subdirectory of inputdir holding the anonymized tree (pl-dicom_anonymize "
        f"output). Default: auto-detect -- the directory containing {ANONYMIZER_SUMMARY}."
    ),
)
parser.add_argument(
    '--acknowledgeRetainedTags', default='', metavar='TAG[,TAG...]',
    help=(
        "Comma-separated DICOM keywords the anonymization policy keeps on purpose; "
        "the leak scan ignores matches inside these elements. Use the same value "
        "given to pl-dicom_anonymize."
    ),
)
parser.add_argument(
    '--residualMinLength', type=int, default=3,
    help="Shortest original value (or name component) the leak scan searches for.",
)
parser.add_argument(
    '--skipPixelCheck', action='store_true', default=False,
    help="Do not check that PixelData is byte-identical between the two trees.",
)
parser.add_argument(
    '--failOnLeak', action='store_true', default=False,
    help=(
        "Exit 1 if the audit finds a leak (original values in the anonymized "
        "headers, UIDs, paths or non-DICOM files), incomplete pairing (any original "
        "DICOM without a verified anonymized counterpart, or the reverse), or an "
        "integrity error (pixel mismatch, conflicting UID mapping). The audit is "
        "always written first. Without this flag the plugin exits 0 and the result "
        "is in audit_summary.json (overall_status)."
    ),
)


# --------------------------------------------------------------------------
# Locating the two trees
# --------------------------------------------------------------------------

class LayoutError(Exception):
    pass


def locate_trees(inputdir: Path, original_opt: str, anonymized_opt: str) -> tuple[Path, Path]:
    if anonymized_opt:
        anon = (inputdir / anonymized_opt).resolve()
    else:
        found = sorted(p.parent for p in inputdir.rglob(ANONYMIZER_SUMMARY))
        if len(found) != 1:
            raise LayoutError(
                f"expected exactly one {ANONYMIZER_SUMMARY} under inputdir to locate the "
                f"anonymized tree, found {len(found)}; pass --anonymizedDir"
            )
        anon = found[0].resolve()

    root = inputdir.resolve()
    if anon == root:
        raise LayoutError(
            "the anonymized tree is inputdir itself, so the original tree cannot be "
            "separated from it. Join the two parent nodes with pl-topologicalcopy "
            "using --groupByInstance so each lands in its own subdirectory."
        )

    if original_opt:
        orig = (inputdir / original_opt).resolve()
    else:
        candidates = [
            d.resolve() for d in sorted(inputdir.iterdir())
            if d.is_dir() and d.resolve() != anon and d.resolve() not in anon.parents
        ]
        if len(candidates) != 1:
            raise LayoutError(
                f"expected exactly one top-level subdirectory besides the anonymized "
                f"tree, found {len(candidates)}; pass --originalDir"
            )
        orig = candidates[0]

    for label, d in (("original", orig), ("anonymized", anon)):
        if not d.is_dir():
            raise LayoutError(f"{label} tree directory does not exist")
    if orig == anon or orig in anon.parents or anon in orig.parents:
        raise LayoutError("original and anonymized trees must not overlap")
    return orig, anon


# --------------------------------------------------------------------------
# Inventory: every file in both trees, and what the anonymizer said
# --------------------------------------------------------------------------

#: status -> category. "pairing" statuses make the pairing incomplete.
STATUS_CATEGORY = {
    "audited": "ok",
    "not_dicom": "info",                    # non-DICOM original, not passed through
    "redaction_sidecar": "info",            # pl-dicom_pixel_redact bounding-box JSON
    "non_dicom_copied": "warning",          # non-DICOM passed through unexamined (--copyNonDicom)
    "extra_anonymized_file": "warning",     # non-DICOM in anonymized tree with no original
    "failed_deidentification": "pairing",   # anonymizer reported failure
    "not_deidentified": "pairing",          # original DICOM the anonymizer never processed
    "missing_anonymized": "pairing",        # anonymizer says processed; no output file
    "missing_original": "pairing",          # anonymizer lists a path absent from the original tree
    "unmatched_anonymized": "pairing",      # anonymized DICOM with no original
    "anonymized_not_dicom": "pairing",      # original DICOM, but the output is not DICOM
    "unreadable": "pairing",                # either side could not be parsed as DICOM
}


@dataclass
class Entry:
    rel: str
    orig_kind: Optional[str] = None         # "dicom" | "other" | None (absent)
    anon_kind: Optional[str] = None
    anonymizer_status: Optional[str] = None  # from deidentification_summary.json


def _kind(path: Path) -> str:
    return "dicom" if is_dicom_file(path) else "other"


def build_inventory(orig: Path, anon: Path) -> tuple[list[Entry], dict]:
    """
    One Entry per relative path found in either tree or in the anonymizer's
    summary, so every input file is accounted for.
    """
    summary: dict = {}
    entries: dict[str, Entry] = {}

    def entry(rel: str) -> Entry:
        return entries.setdefault(rel, Entry(rel))

    for f in sorted(p for p in orig.rglob("*") if p.is_file()):
        entry(str(f.relative_to(orig))).orig_kind = _kind(f)

    for f in sorted(p for p in anon.rglob("*") if p.is_file()):
        rel = str(f.relative_to(anon))
        if rel == ANONYMIZER_SUMMARY:
            continue
        entry(rel).anon_kind = _kind(f)

    summary_path = anon / ANONYMIZER_SUMMARY
    if summary_path.is_file():
        summary = json.loads(summary_path.read_text())
        for rec in summary.get("files", []):
            entry(str(rec["path"])).anonymizer_status = str(rec.get("status", "unknown"))

    return [entries[k] for k in sorted(entries)], summary


def classify(e: Entry, sidecars: set) -> str:
    """Status for one inventory entry; "pair" means audit it."""
    if e.orig_kind == "dicom":
        if e.anonymizer_status == "failed":
            return "failed_deidentification"
        if e.anon_kind == "dicom":
            return "pair"
        if e.anon_kind == "other":
            return "anonymized_not_dicom"
        if e.anonymizer_status == "processed":
            return "missing_anonymized"
        return "not_deidentified"

    if e.orig_kind == "other":
        if e.rel in sidecars:
            return "redaction_sidecar"
        if e.anon_kind == "dicom":
            return "unmatched_anonymized"
        if e.anon_kind == "other":
            return "non_dicom_copied"
        return "not_dicom"

    # absent from the original tree
    if e.anon_kind == "dicom":
        return "unmatched_anonymized"
    if e.anon_kind == "other":
        return "extra_anonymized_file"
    return "missing_original"        # only the anonymizer summary mentions it


# --------------------------------------------------------------------------
# Per-pair audit
# --------------------------------------------------------------------------

def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def collect_ui_values(ds, prefix="") -> list[tuple[str, str]]:
    """[(element path, UID value)] for every UI element, recursing."""
    out = []
    for elem in ds:
        name = elem.keyword or f"({elem.tag.group:04X},{elem.tag.element:04X})"
        if elem.VR == "SQ":
            for i, item in enumerate(elem.value or []):
                out.extend(collect_ui_values(item, f"{prefix}{name}[{i}]."))
        elif elem.VR == "UI" and elem.value:
            vals = elem.value if isinstance(elem.value, (list, tuple)) else [elem.value]
            out.extend((prefix + name, str(v).rstrip("\x00 ")) for v in vals if v)
    return out


def audit_pair(e: Entry, orig: Path, anon: Path, xwalk: Crosswalk, needles: NeedleIndex,
               options: Namespace) -> tuple[dict, list[tuple[str, str]]]:
    """Return (record, anonymized UI values) for one original/anonymized pair."""
    ip, ap = orig / e.rel, anon / e.rel
    rec: dict = {}
    try:
        ids = read_dicom(ip)
        dds = read_dicom(ap)
    except Exception as ex:  # noqa: BLE001
        cls, summary = sanitize_exception(ex)
        rec.update(status="unreadable", error_class=cls, error_summary=summary)
        return rec, []

    try:
        changes = diff_file(ids, dds)
        leaks = find_residual_phi_in_file(
            dds, ids, options.residualMinLength, options.acknowledged_tags_set)
        xwalk.add_file(e.rel, ids, dds, changes)
        needles.add(phi_needles(ids, options.residualMinLength))
        needles.add(uid_needles(ids))
        ui_values = collect_ui_values(getattr(dds, "file_meta", None) or [], "file_meta.")
        ui_values += collect_ui_values(dds)
    except Exception as ex:  # noqa: BLE001
        cls, summary = sanitize_exception(ex)
        rec.update(status="unreadable", error_class=cls, error_summary=summary)
        return rec, []

    actions = Counter(c.action for c in changes)
    rec.update(
        status="audited",
        patient_key=xwalk.patient_key(ids),
        original_sha256=file_sha256(ip),
        anonymized_sha256=file_sha256(ap),
        action_counts=dict(sorted(actions.items())),
        identifying_retained=sorted({c.keyword for c in changes
                                     if c.action == "retained" and c.keyword in WATCHED_KEYWORDS}),
        changes=[c.as_dict() for c in changes],
        leaks=leaks,
        pixel_integrity=None if options.skipPixelCheck else pixel_integrity(ids, dds),
        pixel_redaction=read_redaction_sidecar(ip),
    )
    return rec, ui_values


# --------------------------------------------------------------------------
# Whole-tree leak scans: paths and non-DICOM files
# --------------------------------------------------------------------------

def scan_anonymized_tree(anon: Path, needles: NeedleIndex) -> tuple[list[dict], Counter]:
    """
    Search the anonymized tree's relative paths, and the contents of every
    non-DICOM file in it (including the anonymizer's own summary), for any
    original value seen anywhere in the run.
    """
    rows: list[dict] = []
    stats: Counter = Counter()
    for f in sorted(p for p in anon.rglob("*") if p.is_file()):
        rel = str(f.relative_to(anon))
        for token, src in needles.search(rel):
            rows.append({"file": rel, "location": "<path>", "kind": "path",
                         "source_keyword": src, "matched": token, "occurrences": 1})
        if is_dicom_file(f):
            continue
        stats["non_dicom_scanned"] += 1
        try:
            with open(f, "rb") as fh:
                data = fh.read(NON_DICOM_SCAN_LIMIT + 1)
        except OSError:
            stats["non_dicom_unreadable"] += 1
            continue
        if len(data) > NON_DICOM_SCAN_LIMIT:
            stats["non_dicom_truncated"] += 1
            data = data[:NON_DICOM_SCAN_LIMIT]
        for token, src in needles.search(data.decode("latin-1")):
            rows.append({"file": rel, "location": "<content>", "kind": "non_dicom_content",
                         "source_keyword": src, "matched": token, "occurrences": 1})
    return rows, stats


# --------------------------------------------------------------------------
# Writers
# --------------------------------------------------------------------------

RESTRICTED_README = """\
THIS DIRECTORY CONTAINS PROTECTED HEALTH INFORMATION.

It is the re-identification key for an anonymized DICOM dataset: original
patient names and IDs, accession numbers, UIDs and dates, mapped to their
anonymized values. Anyone with this directory and the anonymized dataset
can re-identify every patient.

Keep it under the same (or stricter) access controls as the original data,
never alongside the anonymized dataset, and delete it when your retention
policy says so. See the pl-dicom_audit README, "Sensitivity and access
control".

Files:
  patients.csv          original -> anonymized PatientID / PatientName, date handling
  accessions.csv        original -> anonymized AccessionNumber
  uids.csv              original -> anonymized Study/Series/SOP/FoR UIDs
  dates.csv             every date/time element: original, new, action, offset
  leaks.csv             every original value found in the anonymized output
  pixel_redactions.csv  pixel-stage redaction record per file (if available)
  file_audit.jsonl      one record per file in either tree: status and, for
                        audited pairs, every element changed, removed,
                        added or retained, with before and after values
"""

LEAK_FIELDS = ["file", "location", "kind", "source_keyword", "matched", "occurrences"]


def write_csv(path: Path, rows, fieldnames: list[str]) -> int:
    n = 0
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        for row in rows:
            w.writerow(row)
            n += 1
    return n


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

@chris_plugin(
    parser=parser,
    title='DICOM anonymization audit',
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
        orig, anon = locate_trees(inputdir, options.originalDir, options.anonymizedDir)
        inventory, anon_summary = build_inventory(orig, anon)
    except LayoutError as ex:
        print(f"FATAL: {ex}", file=sys.stderr)
        sys.exit(2)
    except Exception as ex:  # noqa: BLE001
        cls, summary = sanitize_exception(ex)
        print(f"FATAL: could not read input layout ({cls}): {summary}", file=sys.stderr)
        sys.exit(2)

    restricted = outputdir / "restricted"
    restricted.mkdir(parents=True, exist_ok=True)
    (restricted / "README.txt").write_text(RESTRICTED_README)

    sidecars = {str(Path(e.rel).with_suffix(".json")) for e in inventory if e.orig_kind == "dicom"}
    has_summary = bool(anon_summary)

    xwalk = Crosswalk()
    needles = NeedleIndex()
    status_counts: Counter = Counter()
    action_counts: Counter = Counter()
    retained_identifying: Counter = Counter()
    pixel_counts: Counter = Counter()
    redaction_counts: Counter = Counter()
    entity_counts: Counter = Counter()
    leak_by_keyword: Counter = Counter()
    leak_rows: list[dict] = []
    leak_file_hashes: set = set()
    header_leak_files = 0
    reported_uid_leaks: set = set()
    anon_ui: dict[str, list] = {}           # anonymized UI value -> [count, rel, element path]
    pixel_mismatch_files: list[str] = []
    unlisted: list[str] = []
    total_boxes = 0
    redaction_rows: list[dict] = []
    file_index: list[dict] = []

    with open(restricted / "file_audit.jsonl", "w") as log:
        for i, e in enumerate(inventory, 1):
            h = relpath_hash(e.rel)
            rec: dict = {
                "path": e.rel, "path_hash": h,
                "original": e.orig_kind, "anonymized": e.anon_kind,
                "anonymizer_status": e.anonymizer_status,
            }
            st = classify(e, sidecars)
            if st == "pair":
                result, ui_values = audit_pair(e, orig, anon, xwalk, needles, options)
                rec.update(result)
                st = rec["status"]
                if st == "audited" and has_summary and e.anonymizer_status is None:
                    rec["unlisted_in_anonymizer_summary"] = True
                    unlisted.append(h)
                for path, v in ui_values:
                    slot = anon_ui.setdefault(v, [0, e.rel, path])
                    slot[0] += 1
            else:
                rec["status"] = st
                if st == "failed_deidentification" and (orig / e.rel).is_file():
                    rec["pixel_redaction"] = read_redaction_sidecar(orig / e.rel)

            log.write(json.dumps(rec, default=str) + "\n")
            status_counts[st] += 1
            file_index.append({"path_hash": h, "status": st,
                               **({"anonymized_sha256": rec["anonymized_sha256"]}
                                  if "anonymized_sha256" in rec else {})})
            action_counts.update(rec.get("action_counts", {}))
            retained_identifying.update(rec.get("identifying_retained", []))

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
                    "file": e.rel, "status": pr["status"], "boxes": pr.get("boxes", 0),
                    "entity_types": ";".join(f"{k}={v}" for k, v in pr.get("entity_types", {}).items()),
                    "min_score": pr.get("min_score", ""), "max_score": pr.get("max_score", ""),
                    "pixel_integrity": rec.get("pixel_integrity") or "",
                })
            if rec.get("leaks"):
                header_leak_files += 1
                leak_file_hashes.add(h)
                for hit in rec["leaks"]:
                    leak_by_keyword[hit["keyword"]] += 1
                    if hit["kind"] == "uid":
                        reported_uid_leaks.add(hit["matched"])
                    leak_rows.append({"file": e.rel, "location": hit["path"], "kind": hit["kind"],
                                      "source_keyword": hit["source_keyword"],
                                      "matched": hit["matched"], "occurrences": 1})

            category = STATUS_CATEGORY.get(st, "pairing")
            flag = {"ok": "OK   ", "info": "SKIP ", "warning": "WARN "}.get(category, "FAIL ")
            extra = ""
            if rec.get("leaks"):
                flag, extra = "FAIL ", f" leak in {len(rec['leaks'])} element(s)"
            elif pi == "mismatch":
                flag, extra = "FAIL ", " PixelData differs between trees"
            print(f"[{flag}] file#{i} ({h}): {st}{extra}", file=sys.stderr)

    # -- cross-file UID leaks: an original UID of ANY file, found anywhere --
    leaked_uids = set(reported_uid_leaks)
    for v, (count, rel, path) in sorted(anon_ui.items()):
        if needles.tokens.get(v) not in UID_SOURCES or v in reported_uid_leaks:
            continue
        leaked_uids.add(v)
        leak_file_hashes.add(relpath_hash(rel))
        leak_rows.append({"file": rel, "location": path, "kind": "uid",
                          "source_keyword": needles.tokens[v] + " (another file)",
                          "matched": v, "occurrences": count})
    uid_leak_values = len(leaked_uids)

    # -- paths and non-DICOM files of the anonymized tree --------------------
    tree_rows, tree_stats = scan_anonymized_tree(anon, needles)
    leak_rows.extend(tree_rows)
    path_leaks = sorted({r["file"] for r in tree_rows if r["kind"] == "path"})
    content_leaks = sorted({r["file"] for r in tree_rows if r["kind"] == "non_dicom_content"})
    for rel in path_leaks + content_leaks:
        leak_file_hashes.add(relpath_hash(rel))

    # -- restricted tables ---------------------------------------------------
    n_patients = write_csv(restricted / "patients.csv", xwalk.rows_patients(), [
        "original_patient_id", "original_patient_name", "anonymized_patient_id",
        "anonymized_patient_name", "pseudonym_consistent", "date_handling",
        "date_offset_days", "date_offset_consistent", "n_studies", "n_files"])
    n_acc = write_csv(restricted / "accessions.csv", xwalk.rows_accessions(), [
        "original_accession_number", "anonymized_accession_number",
        "original_patient_id", "original_study_instance_uid", "consistent"])
    uid_rows = list(xwalk.rows_uids())
    write_csv(restricted / "uids.csv", uid_rows, [
        "level", "original_uid", "anonymized_uid", "occurrences", "consistent"])
    write_csv(restricted / "dates.csv", xwalk.dates, [
        "patient_key", "file", "element", "vr", "original", "new", "action", "delta_days"])
    write_csv(restricted / "leaks.csv", leak_rows, LEAK_FIELDS)
    write_csv(restricted / "pixel_redactions.csv", redaction_rows, [
        "file", "status", "boxes", "entity_types", "min_score", "max_score", "pixel_integrity"])

    # -- findings ------------------------------------------------------------
    uid_one_to_many, uid_many_to_one = xwalk.uid_conflicts()
    pseudo_inconsistent, pseudo_collisions = xwalk.pseudonym_findings()
    offsets = [xwalk.patient_date_handling(p) for p in xwalk.patients.values()]
    inconsistent_offsets = sum(1 for _, _, ok in offsets if not ok)
    pairing = {s: n for s, n in status_counts.items() if STATUS_CATEGORY.get(s) == "pairing"}
    sidecars_seen = sum(n for k, n in redaction_counts.items() if k != "no_sidecar")

    findings = []

    def finding(code, category, severity, count, message, **extra):
        if count:
            findings.append({"code": code, "category": category, "severity": severity,
                             "count": count, "message": message, **extra})

    finding("residual_phi", "leak", "error", header_leak_files,
            "anonymized headers contain values from the original headers")
    finding("uid_leak", "leak", "error", uid_leak_values,
            "original Study/Series/SOP/FoR UIDs appear in the anonymized output")
    finding("phi_in_path", "leak", "error", len(path_leaks),
            "anonymized file paths contain original values (pl-dicom_anonymize keeps "
            "the input directory and file names)")
    finding("phi_in_non_dicom", "leak", "error", len(content_leaks),
            "non-DICOM files in the anonymized tree contain original values")
    finding("incomplete_pairing", "pairing", "error", sum(pairing.values()),
            "files without a verified original/anonymized pair", by_status=dict(sorted(pairing.items())))
    finding("nothing_audited", "pairing", "error", int(status_counts["audited"] == 0),
            "no original/anonymized DICOM pair was audited")
    finding("pixel_mismatch", "integrity", "error", len(pixel_mismatch_files),
            "PixelData differs between the original and anonymized files")
    finding("uid_one_to_many", "integrity", "error", len(uid_one_to_many),
            "an original UID was mapped to more than one new UID")
    finding("uid_many_to_one", "integrity", "error", len(uid_many_to_one),
            "different original UIDs were mapped to the same new UID")
    finding("non_dicom_copied", "coverage", "warning", status_counts["non_dicom_copied"],
            "non-DICOM files passed through to the anonymized tree (contents scanned for "
            "known values only)")
    finding("extra_anonymized_file", "coverage", "warning", status_counts["extra_anonymized_file"],
            "non-DICOM files in the anonymized tree with no original")
    finding("unlisted_in_anonymizer_summary", "coverage", "warning", len(unlisted),
            "anonymized DICOM files not listed in the anonymizer summary")
    finding("non_dicom_partially_scanned", "coverage", "warning", tree_stats["non_dicom_truncated"]
            + tree_stats["non_dicom_unreadable"],
            f"non-DICOM files only partially scanned (over {NON_DICOM_SCAN_LIMIT} bytes) or unreadable")
    finding("pseudonym_inconsistent", "consistency", "warning", len(pseudo_inconsistent),
            "a patient received more than one anonymized PatientID")
    finding("pseudonym_collision", "consistency", "warning", len(pseudo_collisions),
            "different patients share one non-empty anonymized PatientID")
    finding("uid_reference_emptied", "consistency", "warning", sum(xwalk.broken_references.values()),
            "Referenced*UID elements were emptied or removed rather than remapped, so those "
            "cross-object links no longer resolve")
    finding("date_offset_inconsistent", "consistency", "warning", inconsistent_offsets,
            "a patient's dates were shifted by more than one offset")
    finding("dates_retained", "consistency", "warning", xwalk.date_actions["retained"],
            "date/time elements kept their original values")
    finding("not_dicom", "coverage", "info", status_counts["not_dicom"],
            "non-DICOM files in the original tree (not anonymized, not passed through)")
    finding("redaction_sidecar", "coverage", "info", status_counts["redaction_sidecar"],
            "pl-dicom_pixel_redact bounding-box files in the original tree")
    if sidecars_seen:
        finding("pixel_redaction_unrecorded", "coverage", "info", redaction_counts["no_sidecar"],
                "audited files with no bounding-box sidecar from pl-dicom_pixel_redact")

    failed = any(f["severity"] == "error" for f in findings)

    restricted_hashes = {
        p.name: file_sha256(p) for p in sorted(restricted.iterdir()) if p.is_file()
    }
    summary = {
        "plugin": "pl-dicom_audit",
        "plugin_version": __version__,
        "pydicom_version": pydicom.__version__,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "elapsed_seconds": round(time.time() - started, 3),
        "anonymizer": {
            "summary_found": has_summary,
            "plugin_version": anon_summary.get("plugin_version"),
            "upstream_version": anon_summary.get("upstream_dicom_anonymizer_version"),
            "overall_status": anon_summary.get("overall_status"),
            "keep_private_tags": anon_summary.get("keep_private_tags"),
            "copy_non_dicom": anon_summary.get("copy_non_dicom"),
            "output_verification_enabled": anon_summary.get("output_verification_enabled"),
            "stopped_early": anon_summary.get("stopped_early"),
        },
        "options": {
            "acknowledged_retained_tags": sorted(options.acknowledged_tags_set),
            "residual_min_length": options.residualMinLength,
            "pixel_check": not options.skipPixelCheck,
            "fail_on_leak": bool(options.failOnLeak),
        },
        "files": {
            "total": len(inventory),
            "by_status": dict(sorted(status_counts.items())),
            "pairing_complete": not pairing and status_counts["audited"] > 0,
        },
        "header_changes": dict(sorted(action_counts.items())),
        "identifying_elements_retained": dict(sorted(retained_identifying.items())),
        "patients": {
            "count": n_patients,
            "pseudonym_inconsistent": len(pseudo_inconsistent),
            "pseudonym_collisions": len(pseudo_collisions),
            "date_offset_consistent": n_patients - inconsistent_offsets,
        },
        "accessions": n_acc,
        "uids": {
            "mapped": len(uid_rows),
            "by_level": dict(sorted(Counter(r["level"] for r in uid_rows).items())),
            "references_emptied": dict(sorted(xwalk.broken_references.items())),
            "one_to_many": len(uid_one_to_many),
            "many_to_one": len(uid_many_to_one),
        },
        "dates": dict(sorted(xwalk.date_actions.items())),
        "leaks": {
            "header_files": header_leak_files,
            "header_by_keyword": dict(sorted(leak_by_keyword.items())),
            "uid_values": uid_leak_values,
            "paths": len(path_leaks),
            "non_dicom_files": len(content_leaks),
            "non_dicom_scanned": tree_stats["non_dicom_scanned"],
            "file_hashes": sorted(leak_file_hashes),
        },
        "pixels": {
            "integrity": dict(sorted(pixel_counts.items())),
            "mismatch_file_hashes": pixel_mismatch_files,
            "redaction": dict(sorted(redaction_counts.items())) if sidecars_seen else {},
            "boxes": total_boxes,
            "entity_types": dict(sorted(entity_counts.items())),
        },
        "findings": findings,
        "overall_status": "fail" if failed else "pass",
        "file_index": file_index,
        "restricted_files_sha256": restricted_hashes,
    }
    (outputdir / "audit_summary.json").write_text(json.dumps(summary, indent=2))

    print("---", file=sys.stderr)
    print(f"files={len(inventory)} " + " ".join(f"{k}={v}" for k, v in sorted(status_counts.items())),
          file=sys.stderr)
    print(f"patients={n_patients} accessions={n_acc} uids={len(uid_rows)} "
          f"leak_rows={len(leak_rows)}", file=sys.stderr)
    for f in findings:
        print(f"{f['severity'].upper()}: {f['code']} ({f['count']}): {f['message']}", file=sys.stderr)
    print(f"Audit {summary['overall_status'].upper()}. PHI-bearing tables are in restricted/.",
          file=sys.stderr)

    if failed and options.failOnLeak:
        sys.exit(1)


if __name__ == '__main__':
    main()
