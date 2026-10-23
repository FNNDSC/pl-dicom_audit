# A ChRIS plugin to audit DICOM de-identification

[![Version](https://img.shields.io/docker/v/fnndsc/pl-dicom_audit?sort=semver)](https://hub.docker.com/r/fnndsc/pl-dicom_audit)
[![MIT License](https://img.shields.io/github/license/fnndsc/pl-dicom_audit)](https://github.com/FNNDSC/pl-dicom_audit/blob/main/LICENSE)
[![ci](https://github.com/FNNDSC/pl-dicom_audit/actions/workflows/ci.yml/badge.svg)](https://github.com/FNNDSC/pl-dicom_audit/actions/workflows/ci.yml)

`pl-dicom_audit` is a **ChRIS ds plugin**. It is the last stage of the
FNNDSC DICOM de-identification pipeline. It compares each identified header
with its de-identified counterpart and writes three things: the
re-identification crosswalk, a per-file change log, and a PHI-free summary
whose pass/fail status can gate the pipeline.

```
Raw DICOM ──► pl-dicom_pixel_redact ──┬──► pl-dicom_anonymize ──┐
              (clean pixels,          │    (clean headers)      │
               identified headers)    │                         │
                                      └──────────┬──────────────┘
                                                 ▼
                              pl-topologicalcopy --groupByInstance
                                                 ▼
                                          pl-dicom_audit
                                                 ▼
                         audit_summary.json  +  restricted/ (PHI)
```

## How it works: diffing two trees

The anonymization plugin keeps nothing it could hand to an auditor:

* dicom-anonymizer holds its old→new UID map in a module-level dictionary
  that disappears when the process exits.
* Dates are replaced with dummy values (`00010101`, etc.), not shifted.
* `deidentification_summary.json` lists per-file status but no mappings.

So this plugin does not depend on the anonymizer recording anything. It
reconstructs every mapping from the data itself. pl-dicom_anonymize keeps
the input directory hierarchy exactly, so each file in the pixel-redaction
output pairs with the file at the same relative path in the anonymization
output. Both headers are read with pydicom and diffed element by element,
recursing into sequences and including File Meta Information.

As a result the audit describes **what actually happened** to each file,
not what a policy says should have happened. It keeps working if the
anonymization profile, dictionary or engine changes.

## Wiring it up in ChRIS

A ds plugin has a single input directory, so the two parent nodes are joined
first:

1. `pl-dicom_pixel_redact` runs on the raw DICOM node (optionally with
   `--save-bboxes`; see *Pixel redaction record* below).
2. `pl-dicom_anonymize` runs as a child of the pixel-redaction node.
3. `pl-topologicalcopy` runs with `--plugininstances <redact_id>,<anonymize_id>`
   and **`--groupByInstance`**, so each parent's output lands in its own
   subdirectory.
4. `pl-dicom_audit` runs as a child of the topological node.

The plugin finds the two trees on its own. The de-identified tree is the
directory that contains `deidentification_summary.json`. The identified
tree is the one other top-level subdirectory. If the layout is anything
else, pass `--anonymizedDir` / `--identifiedDir`. If the join was made
without `--groupByInstance`, the two trees overlap and the plugin exits 2
with an explanation.

## Output

```
outputdir/
├── audit_summary.json          PHI-free; safe for job logs, dashboards, sharing
└── restricted/                 CONTAINS PHI: the re-identification key
    ├── README.txt
    ├── patients.csv            original PatientID/Name → de-identified, date handling, offset
    ├── accessions.csv          original AccessionNumber → de-identified
    ├── uids.csv                original Study/Series/SOP/FoR UID → de-identified, by level
    ├── dates.csv               every DA/DT/TM element: original, new, action, delta_days
    ├── pixel_redactions.csv    per-file pixel redaction record + pixel integrity
    └── file_audit.jsonl        one JSON record per file, listing every header change
```

**`restricted/` is a re-identification key.** Anyone holding it together
with the de-identified dataset can re-identify every patient. Restrict
access to this plugin instance's output the same way you restrict the
original data, and never publish or share it alongside the de-identified
dataset. `audit_summary.json` records the SHA-256 of every restricted file,
so later tampering is detectable without anyone opening the PHI.

### Per-file change log

Each `file_audit.jsonl` record lists every element that changed. Each entry
has its path (e.g. `ReferencedImageSequence[0].ReferencedSOPInstanceUID`),
tag, VR, original and new values, and one of these actions:

| action | meaning |
|---|---|
| `removed` | present in the identified header, absent after de-identification |
| `emptied` | still present, but zero-length |
| `replaced` | present with a different non-empty value |
| `added` | absent before, present after |
| `retained` | unchanged, recorded only for identifying elements and dates |
| `items_removed` / `items_added` | the sequence's item count changed |

Binary values (OB/OW/UN, …) are recorded as SHA-256 + length, not verbatim.
PixelData is excluded here and checked separately.

### Dates

Every date/time element is classified:

| action | meaning |
|---|---|
| `replaced_dummy` | dicom-anonymizer's dummy value (`00010101`, `00010101010101.000000+0000`, `000000.00`) |
| `shifted` | moved to a different real date; `delta_days` recorded |
| `retained`, `removed`, `emptied`, `replaced` | as above |

`patients.csv` reports a per-patient `date_offset_days` only if every shifted
DA/DT element for that patient moved by the same number of days. If they
moved by different amounts, `date_offset_consistent=False` and the summary
raises a warning.

With pl-dicom_anonymize's current defaults, dates come out as
`replaced_dummy` and no offset exists, so date intervals are **not**
preserved. Shift detection is ready for the day the header stage starts
shifting dates.

### Pixel checks

* **Integrity (always on unless `--skipPixelCheck`).** The PixelData of each
  pixel-redacted file must be byte-identical to the de-identified file. That
  is how the audit confirms the header stage did not alter, re-encode or
  replace the redacted pixels.
* **Pixel redaction record.** When pl-dicom_pixel_redact runs with
  `--save-bboxes`, it writes Presidio's bounding boxes next to each output
  DICOM (`<stem>.json`: entity type, score, box). The audit records the box
  count, entity types and score range for each file. A file with no sidecar
  is reported as `no_sidecar`, which does **not** mean nothing was redacted.

## Checks and exit status

The plugin always writes the full audit first, then sets its exit status.

| finding | severity | effect |
|---|---|---|
| `residual_phi`: a value from the identified header (patient name or any of its components, IDs, birth date, accession, institution, physicians, …) appears anywhere in the de-identified header, including nested and private elements | error | exit 1 |
| `pixel_mismatch` | error | exit 1 |
| `uid_one_to_many` / `uid_many_to_one`: one original UID got two new ones, or two originals collapsed into one | error | exit 1 |
| `unpaired_or_unreadable`: a file the anonymizer reported as processed is missing or not valid DICOM | error | exit 1 |
| `deidentification_failed`, `not_deidentified`, `unlisted_deidentified` | warning | none |
| `pseudonym_inconsistent`, `pseudonym_collision` | warning | none |
| `uid_reference_emptied`: `Referenced*UID` elements were emptied, not remapped, so cross-object links no longer resolve | warning | none |
| `date_offset_inconsistent` | warning | none |
| `pixel_redaction_unrecorded` | info | none |

Use `--reportOnly` to always exit 0 and rely on `overall_status` in the
summary instead.

The residual-PHI scan is independent of pl-dicom_anonymize's own
verification, and it is broader. That verification checks a fixed list of
core tags for values that survived byte-for-byte. This scan looks for every
identifying token inside **every** text element. For example, a
`StudyDescription` of `follow-up for Doe` kept by a custom dictionary passes
the anonymizer and fails here. Elements your policy keeps on purpose go in
`--acknowledgeRetainedTags`, using the same value you gave the anonymizer.

### What the anonymizer's defaults look like through this audit

Running the pinned `dicom-anonymizer==1.0.13.post1` (PS3.15 2023e profile)
with no dictionary gives these results:

* `PatientID`, `PatientName` and `AccessionNumber` are **emptied**, so
  `patients.csv` maps every patient to an empty pseudonym. Longitudinal
  linkage across separate runs is not possible. Within a run, the crosswalk
  still records which original patient each file belonged to.
* Study, series and SOP instance UIDs are remapped consistently within the
  run.
* UIDs inside `ReferencedImageSequence` are emptied, which raises
  `uid_reference_emptied`.
* Dates are `replaced_dummy`.
* Private tags are removed.

## CLI options

| Option | Description |
|---|---|
| `--identifiedDir SUBDIR` | identified tree (pixel-redaction output) under inputdir; default: auto-detect |
| `--anonymizedDir SUBDIR` | de-identified tree under inputdir; default: the directory containing `deidentification_summary.json` |
| `--acknowledgeRetainedTags TAG[,TAG...]` | elements the policy keeps on purpose; excluded from the residual-PHI scan |
| `--residualMinLength N` | shortest identifying token searched for (default 3; shorter tokens are too noisy) |
| `--skipPixelCheck` | skip the PixelData integrity comparison |
| `--reportOnly` | always exit 0 once the audit is written |

## Log hygiene

stdout and stderr, which ChRIS exposes as job logs, contain only counts,
finding codes and 12-character path hashes. Those hashes match the ones
pl-dicom_anonymize prints. Exception text is replaced with fixed
descriptions, and pydicom warnings are suppressed, because both can quote
tag values. `audit_summary.json` follows the same rules.

## Limitations

* **The audit itself is PHI**, and so is its input: the topological join
  copies the identified intermediate tree into the audit node's input. The
  pipeline's "delete the intermediate after the header stage" rule
  therefore applies to the join node and the pixel-redaction node, and only
  after this audit has run.
* **Residual-PHI matching is literal.** It finds verbatim and
  case-insensitive substring matches of known values. It does not catch
  reformatted values (`Jane Doe` vs `DOE^JANE` is caught through name
  components, but `01/01/1980` vs `19800101` is not), identifiers shorter
  than `--residualMinLength`, or PHI that was never in a header tag.
* **Pixel PHI is not re-detected.** The pixel checks confirm the redacted
  pixels passed through unchanged and record what pixel-redact reported.
  They do not re-run OCR.
* **Pairing is by relative path.** It relies on pl-dicom_anonymize keeping
  the hierarchy, which that plugin guarantees.

## Development

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
pip install ".[dev]"
pytest -v
```

The dev extra installs `dicom-anonymizer` at the same pin as
pl-dicom_anonymize, so the tests audit trees produced by the real engine.

### Test inside Docker

```bash
docker build --build-arg extras_require=dev -t pl-dicom_audit:dev .
docker run --rm -v "$PWD:/app:ro" -w /app pl-dicom_audit:dev pytest -v -o cache_dir=/tmp/pytest
```

As with pl-dicom_anonymize, the image deletes its source tree after
installing. The volume mount supplies `tests/`, and `-o cache_dir` is needed
because the mount is read-only.

### Running with Docker

```bash
docker run --rm \
    -v $PWD/joined:/incoming:ro \
    -v $PWD/audit:/outgoing \
    ghcr.io/fnndsc/pl-dicom_audit:latest \
    dicom_audit /incoming /outgoing
```
