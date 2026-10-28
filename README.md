# A ChRIS plugin to audit DICOM anonymization

[![Version](https://img.shields.io/docker/v/fnndsc/pl-dicom_audit?sort=semver)](https://hub.docker.com/r/fnndsc/pl-dicom_audit)
[![MIT License](https://img.shields.io/github/license/fnndsc/pl-dicom_audit)](https://github.com/FNNDSC/pl-dicom_audit/blob/main/LICENSE)
[![ci](https://github.com/FNNDSC/pl-dicom_audit/actions/workflows/ci.yml/badge.svg)](https://github.com/FNNDSC/pl-dicom_audit/actions/workflows/ci.yml)

`pl-dicom_audit` is a **ChRIS ds plugin** that records what
[pl-dicom_anonymize](https://github.com/FNNDSC/pl-dicom_anonymize) changed.

pl-dicom_anonymize writes only a status summary
(`deidentification_summary.json`). It keeps no record of which original
identifier became which pseudonym, which UID became which, or what happened to
each date: the upstream engine holds its UID map in memory and discards it when
the process exits. This plugin rebuilds that record from the data itself. It
pairs every original DICOM with its anonymized counterpart, compares the two
with pydicom, and writes:

* **what changed in each file**: every element changed, removed, added or
  retained, with before and after values;
* **the mappings**: PatientID/PatientName, Study/Series/SOP Instance UIDs,
  accession numbers, and every date/time element;
* **leaks**: original values found anywhere in the anonymized output;
* **an account of every file**: unmatched, skipped, failed and non-DICOM files
  are all listed, so nothing in either tree is silently left out.

The PHI-bearing part of the result goes into a separate `restricted/`
directory. A PHI-free summary sits next to it, and the job log contains only
counts and hashes.

## Contents

* [Where it sits in a pipeline](#where-it-sits-in-a-pipeline)
* [Inputs](#inputs)
* [Outputs](#outputs)
* [Leak scan](#leak-scan)
* [File accounting](#file-accounting)
* [Findings and exit status](#findings-and-exit-status)
* [Options](#options)
* [Usage](#usage)
* [Sensitivity and access control](#sensitivity-and-access-control)
* [Log hygiene](#log-hygiene)
* [Limitations](#limitations)
* [Development and testing](#development-and-testing)

## Where it sits in a pipeline

```
original DICOM node ──┬──► pl-dicom_anonymize ──┐
 (e.g. pl-dircopy, or │                         │
  pl-dicom_pixel_     └───────────┬─────────────┘
  redact output)                  ▼
                 pl-topologicalcopy --groupByInstance
                                  ▼
                           pl-dicom_audit
                                  ▼
              audit_summary.json  +  restricted/ (PHI)
```

The "original" side is whatever pl-dicom_anonymize read. That's usually the raw
upload, or the output of pl-dicom_pixel_redact (clean pixels, identified
headers) when pixel scrubbing runs first. Either way, the audit compares
headers before and after pl-dicom_anonymize.

## Inputs

A ds plugin has one input directory, so the two parent nodes are joined first
with `pl-topologicalcopy --groupByInstance`, which puts each parent's output in
its own subdirectory:

```
inputdir/
├── pl-dircopy_1/                    original tree
│   └── p01/s1/1.dcm …
└── pl-dicom_anonymize_2/            anonymized tree
    ├── deidentification_summary.json
    └── p01/s1/1.dcm …
```

* **Anonymized tree.** Found automatically as the directory containing
  `deidentification_summary.json`. Override it with `--anonymizedDir`.
* **Original tree.** Found automatically as the one other top-level
  subdirectory. Override it with `--originalDir`.
* **Pairing.** Files are paired by relative path. pl-dicom_anonymize keeps
  the input hierarchy exactly, so `pl-dircopy_1/p01/s1/1.dcm` pairs with
  `pl-dicom_anonymize_2/p01/s1/1.dcm`.
* **DICOM detection.** By content (`DICM` at byte 128), not by extension,
  exactly as pl-dicom_anonymize does it. Files whose File Meta Information is
  malformed are rejected, not parsed leniently.
* **Without an anonymizer summary.** If you point `--anonymizedDir` at
  another tool's output, the plugin still pairs by path. It just can't tell
  "failed" from "never processed".
* **Pixel redaction records.** If the original tree is pl-dicom_pixel_redact
  output run with `--save-bboxes`, its `<stem>.json` bounding-box files are
  recognised and summarised (see `pixel_redactions.csv`).

If the layout is ambiguous (no summary, two summaries, extra top-level
directories), or the join was made without `--groupByInstance`, the plugin
exits 2 with an explanation and writes nothing.

## Outputs

```
outputdir/
├── audit_summary.json        no PHI: counts, findings, path hashes, file hashes
└── restricted/               PHI: the re-identification key
    ├── README.txt
    ├── patients.csv
    ├── accessions.csv
    ├── uids.csv
    ├── dates.csv
    ├── leaks.csv
    ├── pixel_redactions.csv
    └── file_audit.jsonl
```

### `restricted/`: contains PHI

| file | one row per | columns |
|---|---|---|
| `patients.csv` | original patient | `original_patient_id`, `original_patient_name`, `anonymized_patient_id`, `anonymized_patient_name`, `pseudonym_consistent`, `date_handling`, `date_offset_days`, `date_offset_consistent`, `n_studies`, `n_files` |
| `accessions.csv` | original accession number | `original_accession_number`, `anonymized_accession_number`, `original_patient_id`, `original_study_instance_uid`, `consistent` |
| `uids.csv` | original UID that was replaced | `level` (study / series / sop / frame_of_reference / other), `original_uid`, `anonymized_uid`, `occurrences`, `consistent` |
| `dates.csv` | date/time element (DA, DT, TM) | `patient_key`, `file`, `element`, `vr`, `original`, `new`, `action`, `delta_days` |
| `leaks.csv` | original value found in the output | `file`, `location` (element path, `<path>` or `<content>`), `kind` (text / uid / path / non_dicom_content), `source_keyword`, `matched`, `occurrences` |
| `pixel_redactions.csv` | file with a pixel-redaction record | `file`, `status`, `boxes`, `entity_types`, `min_score`, `max_score`, `pixel_integrity` |
| `file_audit.jsonl` | **file in either tree** | see below |

Each `file_audit.jsonl` record has these fields:

* `path`, `path_hash`
* `original` and `anonymized`: `dicom`, `other`, or `null` if the file is
  absent from that tree
* `anonymizer_status`, as reported in `deidentification_summary.json`
* `status` (see [File accounting](#file-accounting))

For an audited pair, the record also has:

* `original_sha256`, `anonymized_sha256`
* `patient_key`
* `action_counts`
* `identifying_retained`: identifying keywords that kept their value
* `leaks`
* `pixel_integrity`
* `changes`: one entry per element

Each `changes` entry looks like this:

```json
{"path": "ReferencedImageSequence[0].ReferencedSOPInstanceUID",
 "tag": "(0008,1155)", "keyword": "ReferencedSOPInstanceUID", "vr": "UI",
 "action": "emptied", "original": "1.2.826.0.1…", "new": ""}
```

| action | meaning |
|---|---|
| `replaced` | present in both with different non-empty values |
| `emptied` | still present, now zero-length |
| `removed` | present in the original, absent from the anonymized file |
| `added` | absent from the original, present in the anonymized file |
| `retained` | unchanged (recorded for every non-empty element) |
| `items_removed` / `items_added` | the sequence's item count changed |

Sequences are compared item by item, and File Meta Information is included
(`file_meta.*`). Binary values (OB/OW/UN, …) are recorded as SHA-256 + length.
PixelData is not diffed. Instead, each pair gets a `pixel_integrity` result:

| result | meaning | severity |
|---|---|---|
| `match` | byte-identical in both files | ok |
| `absent_both` | neither file has PixelData (e.g. a structured report) | ok |
| `not_compared` | present in both; comparison skipped by `--skipPixelCheck` | ok |
| `mismatch` | present in both, different bytes | error (`pixel_mismatch`) |
| `absent_in_anonymized` / `absent_in_original` | present in only one file | error (`pixel_missing`) |

`--skipPixelCheck` skips only the byte comparison. A file that lost its pixels
is always an error.

Files are also checked for completeness when read. pydicom reads a truncated
file without complaint and returns whatever it parsed before the end, so the
plugin itself rejects, as `unreadable`:

* files that end part-way through an element;
* native (uncompressed) PixelData shorter than Rows × Columns × frames
  require;
* datasets without a SOP Class/Instance UID.

A file cut exactly on an element boundary is indistinguishable from a valid
shorter file. The pixel-presence check and the diff (a run of `removed`
elements) are what expose those.

Each date is classified as one of:

* `replaced_dummy`: dicom-anonymizer's `00010101` / `000000.00` / … values
* `shifted`: a different real date, with `delta_days` recorded
* `retained`, `emptied`, `removed`, or `replaced`

`patients.csv` reports a per-patient offset only if every shifted date for that
patient moved by the same number of days.

### `audit_summary.json`: no PHI

* **Versions.** The plugin's own, plus the anonymizer's settings as recorded
  in its summary.
* **Files.** Counts by status, and `pairing_complete`.
* **Header changes.** Counts by action, plus which identifying elements were
  retained.
* **Mappings.** Patient and accession counts, UID counts by level, and UID
  mapping conflicts.
* **Dates.** Counts by date action.
* **Leaks.** Counts by kind and keyword, plus the path hashes of affected
  files.
* **Pixels.** Integrity and redaction counts.
* **Findings.** `findings` and `overall_status` (`pass`/`fail`).
* **`file_index`.** Every file's path hash and status, plus the anonymized
  file's SHA-256 for audited pairs.
* **`restricted_files_sha256`.** The SHA-256 of every file in `restricted/`,
  so tampering can be detected without opening the PHI.

## Leak scan

The plugin searches the anonymized output for values taken from the original
headers. This check is independent of pl-dicom_anonymize's own verification and
broader than it: that verification compares a fixed list of core tags for
values that survived byte-for-byte.

| what is searched | for what | match |
|---|---|---|
| every element of each anonymized file, including nested sequences and File Meta; private OB/OW/UN elements and EncapsulatedDocument are decoded as text | that file's original names (and each name component), IDs, birth date, address, phone, accession, institution, physicians, operators | case-insensitive, see below |
| every UI element of each anonymized file | that file's original Study/Series/SOP/FoR Instance UIDs | exact |
| every UI value in the whole anonymized tree | **any** file's original instance UIDs (e.g. a reference that still points to another file's original SOP Instance UID) | exact |
| every relative path in the anonymized tree | every value above, from every file | case-insensitive, see below |
| every non-DICOM file in the anonymized tree, including `deidentification_summary.json` | every value above, from every file | case-insensitive, see below (first 64 MiB) |

How a value matches depends on its shape:

* **A single word** (letters and digits only: a name component like `ANN`, an
  ID like `MRN001`, a date) matches only as a **whole word**: not run into
  other letters or digits. So `DOE` is found in `Doe_Jane/`, `follow-up doe`
  and `DOE^JANE`, but `ANN` is not found in `SCANNER`, `ZED` not in
  `ANONYMIZED`, and a short accession number not inside a hex hash.
* **Anything else** (a full name with `^`, an institution with spaces, a UID
  with dots) matches as a substring.

Standard binary elements other than PixelData (overlays, LUTs, icon images…)
are not searched. Each anonymized file's record lists them, and the summary
counts them by keyword under `binary_not_scanned`.

Two leaks come up often enough to call out:

* **Folder and file names.** pl-dicom_anonymize copies paths verbatim, so a
  PACS export laid out as `Doe_Jane/…` or `<StudyInstanceUID>/…` carries PHI
  straight into the anonymized node. Its own `deidentification_summary.json`
  repeats those paths. Both are reported as `phi_in_path` and
  `phi_in_non_dicom`.
* **Free text kept by a custom dictionary.** For example, a
  `StudyDescription` of `follow-up for Doe` under `{"StudyDescription":
  "keep"}` passes pl-dicom_anonymize's verification and fails here.

Elements your policy keeps on purpose go in `--acknowledgeRetainedTags`, using
the same value you gave pl-dicom_anonymize. The scan skips them.

## File accounting

Every relative path found in either tree or in the anonymizer's summary gets
exactly one status:

| status | meaning | category |
|---|---|---|
| `audited` | original and anonymized DICOM paired and compared | ok |
| `failed_deidentification` | the anonymizer reported a failure; no output | pairing |
| `not_deidentified` | original DICOM the anonymizer never processed (its `--pattern` missed it, or it stopped early) | pairing |
| `missing_anonymized` | the anonymizer says processed, but there is no output file | pairing |
| `missing_original` | the anonymizer's summary lists a path absent from the original tree | pairing |
| `unmatched_anonymized` | anonymized DICOM with no original counterpart | pairing |
| `anonymized_not_dicom` | the original is DICOM but the output at that path is not | pairing |
| `unreadable` | either side could not be parsed as conformant DICOM, or is truncated or empty | pairing |
| `dicom_without_preamble` | a DICOM dataset without the 128-byte preamble and `DICM` prefix. pl-dicom_anonymize skips these as non-DICOM, so the image is missing from the anonymized dataset | pairing |
| `non_dicom_copied` | non-DICOM passed through unexamined (`--copyNonDicom`); content is scanned for leaks | warning |
| `extra_anonymized_file` | non-DICOM in the anonymized tree with no original | warning |
| `not_dicom` | non-DICOM original, not passed through | info |
| `redaction_sidecar` | pl-dicom_pixel_redact bounding-box JSON | info |

Pairing is **complete** only when no file has a `pairing` status and at least
one pair was audited.

## Findings and exit status

The audit is always written in full before the exit status is decided.

| exit | when |
|---|---|
| 0 | the audit was written (with `--failOnLeak`: and no error finding) |
| 1 | `--failOnLeak` is set and an error finding was raised |
| 2 | the input layout could not be resolved (nothing written), or the audit failed part-way (ignore any partial output) |

Without `--failOnLeak`, the plugin exits 0 and you read `overall_status` from
`audit_summary.json`. Set the flag when the audit should stop a pipeline.

| finding | category | severity |
|---|---|---|
| `residual_phi`: original values in anonymized headers | leak | error |
| `uid_leak`: original instance UIDs in the anonymized output | leak | error |
| `phi_in_path`: original values in anonymized file paths | leak | error |
| `phi_in_non_dicom`: original values in non-DICOM files of the anonymized tree | leak | error |
| `incomplete_pairing`: any `pairing` status above (broken down by status) | pairing | error |
| `nothing_audited`: no pair was audited | pairing | error |
| `pixel_mismatch`: PixelData differs between the trees | integrity | error |
| `pixel_missing`: PixelData present in only one of the pair | integrity | error |
| `uid_one_to_many` / `uid_many_to_one`: inconsistent UID mapping | integrity | error |
| `non_dicom_copied`, `extra_anonymized_file`, `unlisted_in_anonymizer_summary`, `non_dicom_partially_scanned` | coverage | warning |
| `pseudonym_inconsistent`, `pseudonym_collision`, `uid_reference_emptied`, `date_offset_inconsistent`, `dates_retained` | consistency | warning |
| `not_dicom`, `redaction_sidecar`, `pixel_redaction_unrecorded`, `binary_not_scanned` | coverage | info |

`--failOnLeak` also fails on the integrity errors. A pixel mismatch can mean
the anonymized file does not carry the scrubbed pixels, and a many-to-one UID
mapping merges distinct studies. Neither should pass silently.

### What pl-dicom_anonymize's defaults look like through this audit

Run with no dictionary, pl-dicom_anonymize 1.2.0 (dicom-anonymizer
1.0.13.post1, PS3.15 2023e profile) produces this:

* PatientID, PatientName and AccessionNumber are **emptied**, so every patient
  maps to an empty pseudonym. Within a run, `patients.csv` still records which
  original patient each file belonged to.
* Study, series and SOP Instance UIDs are remapped consistently within the
  run.
* UIDs inside `ReferencedImageSequence` are **emptied**, not remapped
  (`uid_reference_emptied`).
* Dates become dummy values (`replaced_dummy`), so date intervals are lost.
* Private tags are removed.
* Paths are copied verbatim (see [Leak scan](#leak-scan)).

## Options

| option | default | description |
|---|---|---|
| `--originalDir SUBDIR` | auto | subdirectory of inputdir holding the original tree |
| `--anonymizedDir SUBDIR` | auto | subdirectory of inputdir holding the anonymized tree |
| `--acknowledgeRetainedTags TAG[,TAG…]` | none | DICOM keywords the policy keeps on purpose; excluded from the leak scan |
| `--residualMinLength N` | 3 | shortest original value (or name component) searched for. Raise it if short IDs cause false positives |
| `--skipPixelCheck` | off | skip the byte-for-byte PixelData comparison (missing pixels are still an error) |
| `--failOnLeak` | off | exit 1 on any leak, incomplete pairing or integrity error |
| `-V`, `--version` | | print the version |

## Usage

### In ChRIS

1. Run `pl-dicom_anonymize` as a child of the node holding the original DICOMs.
2. Run `pl-topologicalcopy` on the original node and the anonymize node, with
   `--plugininstances <original_id>,<anonymize_id>` and `--groupByInstance`.
3. Run `pl-dicom_audit` as a child of the topological node, usually with
   `--failOnLeak`, and with the same `--acknowledgeRetainedTags` you gave the
   anonymizer.
4. Before sharing the anonymized data, read the audit node's
   `audit_summary.json` (or rely on `--failOnLeak` having stopped the run).
   Then follow [Sensitivity and access control](#sensitivity-and-access-control).

The plugin descriptor CUBE needs is printed by
`chris_plugin_info --dock-image <image> dicom_audit` (standard `chris_plugin`
tooling). CI uploads it on every semver tag push.

### With Docker

```bash
docker run --rm \
    -v $PWD/joined:/incoming:ro \
    -v $PWD/audit:/outgoing \
    ghcr.io/fnndsc/pl-dicom_audit:latest \
    dicom_audit --failOnLeak /incoming /outgoing
```

To reproduce the ChRIS layout locally:

```bash
mkdir -p joined/original
cp -r raw/. joined/original/
docker run --rm -v $PWD/raw:/incoming:ro -v $PWD/joined/anonymized:/outgoing \
    ghcr.io/fnndsc/pl-dicom_anonymize:1.2.0 dicom_anonymize /incoming /outgoing
docker run --rm -v $PWD/joined:/incoming:ro -v $PWD/audit:/outgoing \
    ghcr.io/fnndsc/pl-dicom_audit:latest dicom_audit --failOnLeak /incoming /outgoing
```

### From the command line

```bash
pip install -r requirements.txt && pip install .
dicom_audit [--originalDir SUBDIR] [--anonymizedDir SUBDIR] [--failOnLeak] INPUTDIR OUTPUTDIR
```

## Sensitivity and access control

**The audit log is a re-identification key.** `restricted/` maps every
anonymized identifier, UID and date back to the original patient. Anyone who
holds it together with the anonymized data can re-identify every patient. Treat
it at least as strictly as the original identified data.

In ChRIS, access is granted per **feed**: whoever can see a feed can browse
every node's output files and job logs in it. The audit node cannot be put
anywhere safer than its parents, because its input (the topological join)
already contains a full copy of the original, identified DICOMs. So the
recommendations are about the feed as a whole:

1. **Treat the whole feed as PHI.** It holds the original data, the join copy
   and the re-identification key. Never make it public. Share it only with the
   named people authorized to re-identify (for example, an honest broker or
   the data custodian), not with the researchers who will receive the
   anonymized data.
2. **Release anonymized data from a separate feed.** Once the audit passes,
   start a new feed from the anonymize node's output (for example, with
   `pl-dircopy` pointed at that node's output path) and share that feed. That
   way, sharing the anonymized dataset never grants access to the audit or
   the originals.
3. **Attach nothing below the audit node** except tools run by the same
   authorized people. A child node receives `restricted/` as its input and
   could republish it.
4. **Choose a compute resource approved for PHI.** The plugin runs wherever
   CUBE schedules it, and its input is staged there.
5. **Keep a copy only where your policy requires one.** If the key must be
   retained (to answer re-identification requests, for example), download
   `restricted/` to storage approved for PHI, and record
   `restricted_files_sha256` from the summary to detect later changes. Then
   delete the feed (or the join and audit nodes) when the retention period
   ends. CUBE administrators and the storage backend's administrators can read
   every feed, so storage policy applies to them too.
6. **What is safe to share.** `audit_summary.json` and the job log contain no
   names, IDs, UIDs, dates or paths. They do contain path hashes: the first
   12 hex characters of an **unsalted** SHA-256 of each relative path (the
   same hash pl-dicom_anonymize prints, which is what lets the two logs be
   correlated). An unsalted hash hides a path only if it can't be guessed.
   When paths follow a predictable pattern (`<Surname>_<Given>/…`,
   `<MRN>/…`, `<AccessionNumber>/…`), anyone with a candidate list of
   patients can hash every candidate path and see which ones match, i.e.
   confirm who is in the dataset. So the summary and job log are safe to
   share **only** when paths carry no identifiers (no `phi_in_path`
   finding). Otherwise treat them as internal to the people who can see the
   original data.

If you need the anonymized output without any re-identification key at all,
don't keep `restricted/`: let the feed retention policy delete it, or remove
the audit node once its summary has been reviewed.

## Log hygiene

stdout and stderr, which ChRIS shows as the job log, contain only:

* the banner;
* one line per file with its sequence number, 12-character path hash and
  status (the same hash pl-dicom_anonymize prints for that file);
* totals, finding codes and counts.

The log never contains identifiers, original values, UIDs or relative paths.
Exception text is replaced with fixed descriptions, pydicom warnings are
suppressed for the whole run (pydicom validates lazily, when an element is
first accessed, and its warnings quote the value), and any unexpected error is
reported by class and a fixed description, never a traceback, because all of
these can quote paths or tag values. `audit_summary.json` follows the
same rules. Tests assert this for clean and leaking runs alike.

## Limitations

* **Literal matching.** The leak scan finds verbatim, case-insensitive
  occurrences of known values and of name components. It misses:
  * reformatted values (`01/01/1980` versus `19800101`);
  * values shorter than `--residualMinLength`;
  * PHI that was never in a header element.
* **False positives.** A short name component that is also a common word
  (`ANN`, `MAY`, `LEE`) still matches wherever that word appears on its own.
  Check `leaks.csv`, and raise `--residualMinLength` if needed. Conversely,
  an ID embedded in a longer alphanumeric string (`MRN001234` when the ID is
  `001234`) is not matched.
* **Pixel PHI is not detected.** The pixel check only confirms PixelData passed
  through unchanged. Burned-in text is pl-dicom_pixel_redact's job.
* **Cross-file text in headers is not checked.** Each file's headers are
  searched for **that file's own** names, IDs, dates and other text values.
  Patient A's name sitting in patient B's header (a mis-filed study, a
  comparison-study description naming another patient) is **not** detected.
  Only original UIDs, file paths and non-DICOM files are searched for every
  patient's values.
* **Some binary elements are not searched.** Standard OB/OW elements other
  than EncapsulatedDocument (overlays, LUTs, icon images) are not decoded as
  text (see `binary_not_scanned`). Text encoded as UTF-16 or compressed
  inside a private blob is not found either.
* **Names run together.** Whole-word matching means a name component fused
  with other letters (`DoeJane`, `JDoe`) is not matched, although
  `Doe_Jane`, `Doe Jane` and `DOE^JANE` are.
* **Scope of the UID mapping.** The mapping covers one anonymizer run, which
  matches pl-dicom_anonymize's own consistency scope.
* **Inherits the sensitivity of its input.** The plugin cannot reduce the
  sensitivity of a feed that already holds the original data. See
  [Sensitivity and access control](#sensitivity-and-access-control).

## Development and testing

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
pip install ".[dev]"          # pytest, dicom-anonymizer, pl-dicom_anonymize 1.2.0
pytest -v
```

| suite | what it covers |
|---|---|
| `tests/test_engine.py` | unit tests: diff, date classification, leak scan, needle index, crosswalk, pairing classification, layout detection |
| `tests/test_audit.py` | integration: `main()` over trees anonymized in-process with the real dicom-anonymizer engine |
| `tests/test_e2e.py` | end to end: the real `dicom_anonymize` CLI, then the `dicom_audit` CLI, as subprocesses; plus the ChRIS descriptor |

The install is non-editable, so the tests exercise the installed package. After
editing source, run `pip install .` again before `pytest`, or you will test the
previous build. The e2e suite is skipped if `dicom_anonymize` is not installed,
except when `CI` is set, where it fails instead.

Inside Docker, as CI runs it:

```bash
docker build --build-arg extras_require=dev -t pl-dicom_audit:dev .
docker run --rm -e CI=true -v "$PWD:/app:ro" -w /app pl-dicom_audit:dev \
    pytest -v -rs -o cache_dir=/tmp/pytest
```

See [MAINTENANCE.md](./MAINTENANCE.md) for dependency upgrades.
