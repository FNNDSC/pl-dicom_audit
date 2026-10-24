# Maintenance and upgrade procedure

## Why everything is pinned

This plugin decides whether an anonymized dataset is safe to release. If an
upstream change silently alters what it parses, matches or reports, that is a
PHI-safety regression, not just a compatibility bug. So:

* `requirements.txt` pins exact versions of the runtime dependencies
  (`chris_plugin`, `pydicom`);
* `setup.py`'s `dev` extra pins the test-only dependencies: `pytest`,
  `dicom-anonymizer` (same pin as pl-dicom_anonymize) and pl-dicom_anonymize
  itself (a release tarball, because it is not on PyPI);
* the `Dockerfile` base image is pinned to a patch tag.

Nothing should float on `latest`, a caret range or an unpinned base image.

## Contracts this plugin relies on

Most upgrade risk comes from these external formats and behaviors. None of
them is enforced by a type checker; the tests listed next to each one are the
only guard.

| contract | where it is used | tests that guard it |
|---|---|---|
| pl-dicom_anonymize keeps the input directory hierarchy exactly | pairing by relative path (`build_inventory`) | `test_e2e.py` (all) |
| `deidentification_summary.json` schema: `files[].path`, `files[].status` ∈ `processed`, `failed`, `skipped_not_dicom`, `copied_non_dicom`; top-level `plugin_version`, `upstream_dicom_anonymizer_version`, `overall_status`, `keep_private_tags`, `copy_non_dicom`, `output_verification_enabled`, `stopped_early` | `build_inventory`, `classify`, summary's `anonymizer` block | `test_e2e.py::test_anonymizer_stops_early_is_incomplete_pairing`, `test_e2e.py::test_clean_pipeline`, `test_audit.py` accounting tests, `test_engine.py::test_classify` |
| path hash = first 12 hex characters of SHA-256 of the relative path, as pl-dicom_anonymize's `safety.relpath_hash` | correlating this job log with the anonymizer's | `test_engine.py::test_relpath_hash_matches_pl_dicom_anonymize` |
| DICOM detection by `DICM` at byte 128, and rejection of files without mandatory File Meta | `is_dicom_file`, `read_dicom` (mirrors pl-dicom_anonymize's `safety.py`) | `test_engine.py::test_is_dicom_and_strict_read`, `test_audit.py::test_unreadable_pair` |
| dicom-anonymizer's dummy date/time values (`00010101`, `00010101010101.000000+0000`, `000000.00`) | `DUMMY_DATE_VALUES` in `audit_engine.py`, mirrored by hand from `dicomanonymizer.simpledicomanonymizer.replace_element_*` | `test_engine.py::test_classify_date`, `test_audit.py::test_date_changes_recorded` |
| PS3.15 2023e profile behavior: PatientName/ID and AccessionNumber emptied, `ReferencedImageSequence` UIDs emptied, private tags removed | documented in the README ("What pl-dicom_anonymize's defaults look like") | `test_audit.py::test_identifier_mapping`, `test_audit.py::test_emptied_uid_references_reported`, `test_audit.py::test_per_file_changes_with_before_and_after` |
| Presidio bounding-box sidecar: `<stem>.json`, a list of `{entity_type, score, left, top, width, height}` (written by pl-dicom_pixel_redact `--save-bboxes` via `DicomImageRedactorEngine._save_bbox_json`) | `read_redaction_sidecar` | `test_engine.py::test_read_redaction_sidecar`, `test_audit.py::test_pixel_redaction_record` |
| `chris_plugin` introspects `main`'s annotations at import time | `dicom_audit.py` must **not** use `from __future__ import annotations` (it turns annotations into strings and `chris_plugin` then rejects `main`) | `test_e2e.py::test_chris_descriptor` (and every test that imports `dicom_audit`) |

## Upgrading pl-dicom_anonymize (the pipeline stage being audited)

Upgrade this whenever FNNDSC releases a new pl-dicom_anonymize, so the e2e
suite always exercises the version actually deployed.

1. Read its changes since the pinned tag, looking for:
   * changes to `deidentification_summary.json` (new or renamed fields, new
     `status` values);
   * changes to path handling (anything other than mirroring the input tree);
   * a change to the upstream `dicom-anonymizer` pin (handle that as below).
2. Bump the tarball URL in `setup.py`'s `dev` extra
   (`https://github.com/FNNDSC/pl-dicom_anonymize/archive/refs/tags/<tag>.tar.gz`).
3. Rebuild the dev image and run the full suite (see *Re-checking CI* below).
   `test_e2e.py` is the suite that matters here.
4. If a new `status` value appears, decide how `classify()` in
   `dicom_audit.py` should treat it, and add a row to
   `test_engine.py::test_classify`. Today an original DICOM with an
   unrecognised status is audited if an output file exists, and counted as
   `not_deidentified` (a pairing error) if not. It must never be classified
   as `not_dicom`, which would hide a missing file.
5. Update the README section "What pl-dicom_anonymize's defaults look like
   through this audit" if the observed behavior changed, and the version
   quoted there.
6. Bump `__version__` (see *Versioning*).

## Upgrading dicom-anonymizer (test dependency)

Keep it at the same version pl-dicom_anonymize pins.

1. Read the upstream changelog for changes to the default rule table and to
   `replace_element_date` / `_date_time` / `_time` (the dummy values).
2. Bump the pin in `setup.py`'s `dev` extra.
3. If the dummy values changed, update `DUMMY_DATE_VALUES` in
   `audit_engine.py`. Otherwise every date is misclassified as `replaced`
   instead of `replaced_dummy`.
4. Run the full suite. Expect failures in the profile-behavior tests listed in
   the contracts table if the default table changed. Those failures are the
   signal to update the README's documented defaults too, not just the
   assertions.

## Upgrading pydicom

This is the riskiest runtime upgrade: the audit's correctness depends on
pydicom's exact data model.

1. Read the release notes for changes to:
   * `Dataset.get` / `__getitem__` / `__contains__` semantics. `get_elem()`
     exists because `Dataset.get(keyword)` returns a bare value, not a
     `DataElement`;
   * `MultiValue`, `PersonName` string rendering and `UN` handling (`render`,
     `_text_values`);
   * `dcmread(force=False)` strictness and File Meta handling (`read_dicom`);
   * dataset writing in the test fixtures. pydicom 3 deprecates
     `is_little_endian`, `is_implicit_VR` and `write_like_original`, which
     `tests/conftest.py::make_dcm` uses.
2. Bump the pin in `requirements.txt`. pl-dicom_anonymize pins pydicom in its
   own `requirements.txt`, but its `setup.py` does not declare it, so pip will
   **not** flag a mismatch when the e2e suite installs both into one
   environment. Keep the two pins aligned by hand.
3. Run the full suite, paying particular attention to `test_engine.py` (diff
   and leak-scan unit tests) and the PHI-hygiene tests:
   `test_audit.py::test_summary_and_logs_are_phi_free`,
   `test_audit.py::test_logs_are_phi_free_even_when_leaking`,
   `test_e2e.py::test_job_log_is_phi_free`.
   pydicom warnings and exception messages can quote values. The plugin
   suppresses warnings and never prints exception text, and these tests
   confirm nothing leaks.

## Upgrading chris_plugin

1. Bump the pin in `requirements.txt` (and check pl-dicom_anonymize's pin).
2. Run the full suite. `test_e2e.py::test_chris_descriptor` checks the
   descriptor CUBE receives: the plugin type, and that every option is present
   with the right type and default.
3. Confirm the `inputdir`/`outputdir` contract of `main` is unchanged.

## Upgrading the base image

`FROM docker.io/python:3.12.1-slim-bookworm` matches pl-dicom_anonymize. Bump
it deliberately, rebuild, and run the full suite. Keep the two plugins on the
same Python minor version, since the e2e suite installs both into one
environment.

## Changing what the plugin outputs

Any new `print`, new field in `audit_summary.json`, or new exception path is a
potential PHI leak into the job log or the shareable summary. Before merging:

* identifiers, original values, UIDs and relative paths may go **only** into
  `restricted/`;
* stdout/stderr and `audit_summary.json` may contain only counts, finding
  codes, keywords, path hashes and file hashes;
* exceptions go through `sanitize_exception`, never `str(exc)`;
* extend the PHI-hygiene tests above to cover the new output, with a leaking
  input as well as a clean one.

A new file in `restricted/` must also be listed in `RESTRICTED_README` and in
the README's output table. Its hash then appears automatically in
`restricted_files_sha256`.

## Tests to re-run, by change

| change | at minimum | then |
|---|---|---|
| any dependency or base image | full suite in the dev image | |
| `audit_engine.py` | `tests/test_engine.py` | full suite |
| `dicom_audit.py` pairing / classification | `tests/test_engine.py::test_classify`, `tests/test_audit.py` | `tests/test_e2e.py` |
| leak scan | `tests/test_engine.py -k residual or needle`, `tests/test_audit.py -k leak` | full suite |
| anything printed or summarised | the three PHI-hygiene tests | full suite |
| options / `@chris_plugin` metadata | `tests/test_e2e.py::test_chris_descriptor` | full suite |

The install is non-editable, so run `pip install .` again before `pytest`
after editing source. Otherwise you test the previous build (inside Docker:
rebuild the image). A quick way to confirm a test guards what you think it
guards is to break that code path on purpose, reinstall, and watch the test
fail.

## Versioning

`__version__` in `dicom_audit.py` is the single source of truth. It is read by
`setup.py`, printed by `--version`, recorded in `audit_summary.json`, and used
by CI to tag the image and the uploaded ChRIS descriptor. Bump it for **any**
change in runtime behavior, including a dependency upgrade that changes what
is parsed, matched or reported. An unchanged version on a behavior change
makes past audits impossible to reproduce.

## Re-checking CI

`.github/workflows/ci.yml` builds the image with `extras_require=dev` and runs
`pytest` **inside** it, against the exact pinned dependencies. It passes
`CI=true`, so the e2e suite fails instead of skipping if pl-dicom_anonymize did
not install. A green run there is the real gate. Check the `-rs` output for
any skipped tests. The `build` job's `needs: [test]` blocks the image push on
a red test run; don't remove it to unblock a build.

This repository does not ship an SBOM or third-party license notices yet.
pl-dicom_anonymize's MAINTENANCE.md describes a working procedure
(`cyclonedx-py` against a clean venv of `requirements.txt`) to adopt if one is
needed.
