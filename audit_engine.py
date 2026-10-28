"""
Core of pl-dicom_audit: diff an identified DICOM header against its
de-identified counterpart and accumulate the audit tables.

Nothing in this module prints or logs. Everything it returns that contains
original values is destined for the restricted part of the audit output;
the CLI layer (dicom_audit.py) decides what may reach stdout/stderr and the
PHI-free summary.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import re
import warnings
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

import pydicom
from pydicom.dataelem import RawDataElement
from pydicom.dataset import Dataset
from pydicom.errors import InvalidDicomError
from pydicom.multival import MultiValue

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

#: Dummy values dicom-anonymizer writes when it "replaces" or "empties" a
#: date/time element (dicomanonymizer.simpledicomanonymizer.replace_element_*).
DUMMY_DATE_VALUES = {
    "DA": "00010101",
    "DT": "00010101010101.000000+0000",
    "TM": "000000.00",
}

DATE_VRS = frozenset(DUMMY_DATE_VALUES)

#: VRs whose values are rendered as a hash + length rather than verbatim.
BINARY_VRS = frozenset({"OB", "OW", "OF", "OD", "OL", "OV", "UN"})

#: VRs searched by the residual-PHI scan.
TEXT_VRS = frozenset({"AE", "DA", "DT", "LO", "LT", "PN", "SH", "ST", "UC", "UT"})

#: Identifying elements. Their retention is called out separately in the
#: summary (an unchanged PatientName matters; an unchanged Modality does not).
WATCHED_KEYWORDS = frozenset({
    "PatientName", "PatientID", "OtherPatientIDs", "OtherPatientNames",
    "OtherPatientIDsSequence", "IssuerOfPatientID", "PatientBirthDate",
    "PatientBirthTime", "PatientSex", "PatientAge", "PatientAddress",
    "PatientTelephoneNumbers", "PatientMotherBirthName", "MilitaryRank",
    "EthnicGroup", "AccessionNumber", "StudyID", "InstitutionName",
    "InstitutionAddress", "InstitutionalDepartmentName",
    "ReferringPhysicianName", "PerformingPhysicianName",
    "NameOfPhysiciansReadingStudy", "OperatorsName", "RequestingPhysician",
    "StationName", "DeviceSerialNumber", "StudyInstanceUID",
    "SeriesInstanceUID", "SOPInstanceUID", "FrameOfReferenceUID",
})

#: Identified-header elements whose values become residual-PHI needles.
RESIDUAL_SOURCE_KEYWORDS = (
    "PatientName", "PatientID", "OtherPatientIDs", "OtherPatientNames",
    "PatientBirthDate", "PatientAddress", "PatientTelephoneNumbers",
    "PatientMotherBirthName", "AccessionNumber", "InstitutionName",
    "InstitutionAddress", "ReferringPhysicianName", "PerformingPhysicianName",
    "NameOfPhysiciansReadingStudy", "OperatorsName", "RequestingPhysician",
)

UID_LEVELS = {
    "StudyInstanceUID": "study",
    "ReferencedStudyInstanceUID": "study",
    "SeriesInstanceUID": "series",
    "ReferencedSeriesInstanceUID": "series",
    "SOPInstanceUID": "sop",
    "ReferencedSOPInstanceUID": "sop",
    "MediaStorageSOPInstanceUID": "sop",
    "FrameOfReferenceUID": "frame_of_reference",
    "ReferencedFrameOfReferenceUID": "frame_of_reference",
}


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def relpath_hash(relative_path: Path | str) -> str:
    """Same 12-hex-char correlation id pl-dicom_anonymize uses in its logs."""
    return sha256_hex(str(relative_path).encode("utf-8"))[:12]


def sanitize_exception(exc: BaseException) -> tuple[str, str]:
    """
    (class name, fixed description) for an exception. pydicom messages can
    quote tag values, so str(exc) is never used.
    """
    name = type(exc).__name__
    known = {
        "InvalidDicomError": "file is not a valid DICOM file",
        "MalformedDicomError": "file has DICOM magic bytes but no conformant File Meta Information, or no SOP Class/Instance UID",
        "TruncatedDicomError": "file is truncated (ends part-way through an element, or PixelData is shorter than the image dimensions require)",
        "FileNotFoundError": "file disappeared or was unreadable",
        "PermissionError": "insufficient filesystem permissions",
        "IsADirectoryError": "expected a file but found a directory",
        "KeyError": "a required DICOM element was missing",
        "ValueError": "a data element could not be parsed",
        "AttributeError": "an unexpected dataset structure was encountered",
        "OSError": "an I/O error occurred while reading",
        "JSONDecodeError": "a JSON file could not be parsed",
    }
    return name, known.get(name, "audit failed with an unexpected internal error")


def is_dicom_file(path: Path) -> bool:
    """Content sniff (DICM at offset 128), as pl-dicom_anonymize does."""
    try:
        with open(path, "rb") as fh:
            fh.seek(128)
            return fh.read(4) == b"DICM"
    except OSError:
        return False


class MalformedDicomError(InvalidDicomError):
    """DICM magic present, but no conformant File Meta Information."""


_REQUIRED_FILE_META = ("MediaStorageSOPClassUID", "MediaStorageSOPInstanceUID", "TransferSyntaxUID")


class TruncatedDicomError(InvalidDicomError):
    """The file ends before its declared content (pydicom reads it silently)."""


#: Elements a dataset must have to count as a DICOM object at all. pydicom
#: returns whatever it parsed before EOF, so a file cut off mid-header comes
#: back as a handful of elements rather than an error.
_REQUIRED_ELEMENTS = ("SOPClassUID", "SOPInstanceUID")


def expected_pixel_bytes(ds: Dataset) -> Optional[int]:
    """
    Byte length native (uncompressed) PixelData must have, from Rows,
    Columns, SamplesPerPixel, BitsAllocated and NumberOfFrames. None when it
    cannot be computed (encapsulated transfer syntax, missing attributes).
    """
    meta = getattr(ds, "file_meta", None)
    ts = getattr(meta, "TransferSyntaxUID", None) if meta is not None else None
    if ts is None or ts.is_compressed:
        return None
    try:
        rows, cols = int(ds.Rows), int(ds.Columns)
        bits = int(ds.BitsAllocated)
        spp = int(ds.get("SamplesPerPixel", 1) or 1)
        frames = int(ds.get("NumberOfFrames", 1) or 1)
    except (AttributeError, TypeError, ValueError):
        return None
    n_bits = rows * cols * spp * frames * bits
    return (n_bits + 7) // 8


UNDEFINED_LENGTH = 0xFFFFFFFF


def check_not_truncated(ds: pydicom.dataset.FileDataset, file_size: int) -> None:
    """
    pydicom stops quietly at end of file, so a truncated file reads "fine".
    Right after dcmread every top-level element is still raw and carries its
    declared length and file offset; use them to detect:

    * an element whose value is shorter than its declared length (cut
      mid-value), and
    * bytes left over after the last element (cut mid-element-header).

    A cut exactly on an element boundary is a valid shorter file and cannot
    be told apart here; the pixel-presence check and the diff catch those.
    Skipped where offsets do not map to file bytes (deflated transfer syntax)
    or the last element has undefined length (encapsulated pixel data,
    undefined-length sequences).
    """
    raws = [r for r in ds._dict.values() if isinstance(r, RawDataElement)]
    for r in raws:
        if r.length != UNDEFINED_LENGTH and r.value is not None and len(r.value) < r.length:
            raise TruncatedDicomError("an element is shorter than its declared length")
    ts = getattr(getattr(ds, "file_meta", None), "TransferSyntaxUID", None)
    if not raws or (ts is not None and ts.is_deflated):
        return
    last = max(raws, key=lambda r: r.value_tell)
    if last.length != UNDEFINED_LENGTH and last.value_tell + last.length != file_size:
        raise TruncatedDicomError("file ends part-way through an element")


def check_complete(ds: Dataset) -> None:
    """Raise if a dataset read without error is nevertheless incomplete."""
    if any(kw not in ds for kw in _REQUIRED_ELEMENTS):
        raise MalformedDicomError("dataset has no SOP Class/Instance UID (empty or cut off)")
    if 0x7FE00010 in ds:
        expected = expected_pixel_bytes(ds)
        actual = len(ds[0x7FE00010].value or b"")
        if expected is not None and actual < expected:
            raise TruncatedDicomError("PixelData is shorter than Rows x Columns x frames require")


def read_dicom(path: Path) -> pydicom.dataset.FileDataset:
    """
    Strict read, as pl-dicom_anonymize does it, plus completeness checks.
    pydicom will happily parse a DICM-prefixed file of garbage, or a file cut
    off part-way, into a partial dataset; diffing that against a real header
    shows "everything removed" and would pass the audit, so such files are
    rejected instead.
    """
    # pydicom warnings can quote values; they must never reach the job log.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        ds = pydicom.dcmread(str(path), force=False)
    meta = getattr(ds, "file_meta", None)
    if meta is None or any(not hasattr(meta, k) for k in _REQUIRED_FILE_META):
        raise MalformedDicomError("missing mandatory File Meta Information")
    check_not_truncated(ds, path.stat().st_size)     # before anything converts raw elements
    check_complete(ds)
    return ds


def looks_like_headerless_dicom(path: Path) -> bool:
    """
    True for a DICOM dataset written without the 128-byte preamble and DICM
    prefix (older ACR-NEMA style exports). pl-dicom_anonymize's content sniff
    skips these as "not DICOM", so they would otherwise vanish from the
    anonymized dataset unnoticed. Only the header is read.
    """
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            ds = pydicom.dcmread(str(path), force=True, stop_before_pixels=True)
        uid = str(ds.get("SOPInstanceUID", "") or "")
        cls = str(ds.get("SOPClassUID", "") or "")
    except Exception:  # noqa: BLE001 - anything unparseable is simply not DICOM
        return False
    return bool(_UID_RE.fullmatch(uid) and _UID_RE.fullmatch(cls))


_UID_RE = re.compile(r"[0-9]+(\.[0-9]+)+")


def get_elem(ds: Dataset, keyword: str):
    """The DataElement for a keyword, or None. (Dataset.get(keyword) returns
    the bare value, and data_element() raises when absent.)"""
    return ds[keyword] if keyword in ds else None


def element_name(elem) -> str:
    if elem.keyword:
        return elem.keyword
    return f"({elem.tag.group:04X},{elem.tag.element:04X})"


def tag_str(elem) -> str:
    return f"({elem.tag.group:04X},{elem.tag.element:04X})"


def render(elem):
    """JSON-safe rendering of an element value."""
    value = elem.value
    if elem.VR in BINARY_VRS or isinstance(value, (bytes, bytearray)):
        raw = bytes(value) if value is not None else b""
        return {"sha256": sha256_hex(raw), "length": len(raw)}
    if value is None:
        return ""
    if isinstance(value, MultiValue):
        return [str(v) for v in value]
    return str(value)


def is_empty(rendered) -> bool:
    if isinstance(rendered, dict):
        return rendered.get("length", 0) == 0
    if isinstance(rendered, list):
        return all(v == "" for v in rendered)
    return rendered == ""


def first_str(rendered) -> str:
    if isinstance(rendered, list):
        return rendered[0] if rendered else ""
    if isinstance(rendered, dict):
        return ""
    return rendered


def _parse_da(value: str) -> Optional[_dt.date]:
    value = value.strip()
    if len(value) != 8 or not value.isdigit():
        return None
    try:
        return _dt.date(int(value[:4]), int(value[4:6]), int(value[6:8]))
    except ValueError:
        return None


# --------------------------------------------------------------------------
# Header diff
# --------------------------------------------------------------------------

@dataclass
class Change:
    path: str
    tag: str
    keyword: str
    vr: str
    action: str           # removed | emptied | replaced | added | retained | items_removed | items_added
    original: object = None
    new: object = None

    def as_dict(self) -> dict:
        d = {"path": self.path, "tag": self.tag, "keyword": self.keyword,
             "vr": self.vr, "action": self.action}
        if self.original is not None:
            d["original"] = self.original
        if self.new is not None:
            d["new"] = self.new
        return d


def diff_datasets(orig: Dataset, new: Dataset, prefix: str = "") -> list[Change]:
    """
    Element-level diff of two datasets, recursing into sequences (items are
    paired by index). PixelData is excluded; it is checked separately.
    """
    changes: list[Change] = []
    tags = sorted(set(orig.keys()) | set(new.keys()))
    for tag in tags:
        if tag == 0x7FE00010:  # PixelData
            continue
        o = orig.get(tag) if tag in orig else None
        n = new.get(tag) if tag in new else None
        ref = o if o is not None else n
        name = element_name(ref)
        path = prefix + name
        vr = ref.VR

        if o is not None and n is None:
            changes.append(Change(path, tag_str(ref), name, vr, "removed",
                                  original=None if vr == "SQ" else render(o)))
            continue
        if o is None and n is not None:
            changes.append(Change(path, tag_str(ref), name, vr, "added",
                                  new=None if vr == "SQ" else render(n)))
            continue

        if vr == "SQ" or n.VR == "SQ":
            o_items = list(o.value or []) if o.VR == "SQ" else []
            n_items = list(n.value or []) if n.VR == "SQ" else []
            for i in range(min(len(o_items), len(n_items))):
                changes.extend(diff_datasets(o_items[i], n_items[i], f"{path}[{i}]."))
            if len(o_items) > len(n_items):
                changes.append(Change(path, tag_str(ref), name, vr, "items_removed",
                                      original=len(o_items), new=len(n_items)))
            elif len(n_items) > len(o_items):
                changes.append(Change(path, tag_str(ref), name, vr, "items_added",
                                      original=len(o_items), new=len(n_items)))
            continue

        ro, rn = render(o), render(n)
        if ro == rn:
            if not is_empty(ro):
                changes.append(Change(path, tag_str(ref), name, vr, "retained", original=ro, new=rn))
            continue
        action = "emptied" if is_empty(rn) else "replaced"
        changes.append(Change(path, tag_str(ref), name, vr, action, original=ro, new=rn))
    return changes


def diff_file(orig: pydicom.dataset.FileDataset, new: pydicom.dataset.FileDataset) -> list[Change]:
    changes = []
    om = getattr(orig, "file_meta", None) or Dataset()
    nm = getattr(new, "file_meta", None) or Dataset()
    changes.extend(diff_datasets(om, nm, "file_meta."))
    changes.extend(diff_datasets(orig, new))
    return changes


# --------------------------------------------------------------------------
# Date classification
# --------------------------------------------------------------------------

def classify_date(change: Change) -> tuple[str, Optional[int]]:
    """
    Return (date_action, delta_days). delta_days is set only for a DA/DT
    value that was moved to a different *real* date (i.e. shifted).
    """
    if change.action in ("removed", "emptied", "retained"):
        return change.action, (0 if change.action == "retained" else None)
    new = first_str(change.new)
    if new == DUMMY_DATE_VALUES.get(change.vr):
        return "replaced_dummy", None
    if change.vr in ("DA", "DT"):
        od = _parse_da(first_str(change.original)[:8])
        nd = _parse_da(new[:8])
        if od and nd and od != nd:
            return "shifted", (nd - od).days
    return "replaced", None


# --------------------------------------------------------------------------
# Residual PHI
# --------------------------------------------------------------------------

def phi_needles(identified: Dataset, min_len: int) -> dict[str, str]:
    """
    {UPPERCASE token: source keyword} from the identified header. Person
    names are also split into their components so a surviving surname is
    caught even when the full name is not.
    """
    needles: dict[str, str] = {}

    def add(token: str, source: str):
        token = token.strip().upper()
        if len(token) >= min_len and token not in {v for v in DUMMY_DATE_VALUES.values()}:
            needles.setdefault(token, source)

    for kw in RESIDUAL_SOURCE_KEYWORDS:
        elem = get_elem(identified, kw)
        if elem is None or elem.value in (None, ""):
            continue
        values = elem.value if isinstance(elem.value, MultiValue) else [elem.value]
        for v in values:
            s = str(v)
            add(s, kw)
            if elem.VR == "PN":
                for part in s.replace("=", "^").split("^"):
                    for word in part.split():
                        add(word, kw)
    return needles


#: Instance-identifying UIDs. Their original values must not survive anywhere
#: in the anonymized output (SOPClassUID etc. are not identifying).
UID_NEEDLE_KEYWORDS = (
    "StudyInstanceUID", "SeriesInstanceUID", "SOPInstanceUID", "FrameOfReferenceUID",
)


def uid_needles(identified: pydicom.dataset.FileDataset) -> dict[str, str]:
    """{original instance UID: source keyword}, including File Meta."""
    out: dict[str, str] = {}
    for kw in UID_NEEDLE_KEYWORDS:
        v = _top(identified, kw)
        if v:
            out.setdefault(v, kw)
    meta = getattr(identified, "file_meta", None)
    if meta is not None:
        v = _top(meta, "MediaStorageSOPInstanceUID")
        if v:
            out.setdefault(v, "MediaStorageSOPInstanceUID")
    return out


#: Standard binary elements that commonly carry text (an embedded PDF/CDA
#: report). Decoded and scanned like private binary elements.
TEXT_BEARING_BINARY = frozenset({0x00420011})          # EncapsulatedDocument


def is_scanned_binary(elem) -> bool:
    """Binary elements the leak scan decodes as text: every UN element, every
    private (odd-group) OB/OW element, and TEXT_BEARING_BINARY."""
    if elem.tag == 0x7FE00010:
        return False
    if elem.VR == "UN":
        return True
    return elem.VR in ("OB", "OW") and (elem.tag.is_private or elem.tag in TEXT_BEARING_BINARY)


def _text_values(elem) -> list[str]:
    """
    Searchable text of an element: text VRs as-is; binary elements chosen by
    is_scanned_binary() decoded as latin-1 (a vendor's private OB blob or an
    embedded report can hold names in plain ASCII). Other binary VRs are not
    searched; unscanned_binary() reports them.
    """
    if is_scanned_binary(elem):
        raw = bytes(elem.value or b"")
        return [raw.decode("latin-1")] if raw else []
    if elem.VR not in TEXT_VRS and elem.VR != "UI":
        return []
    rendered = render(elem)
    values = rendered if isinstance(rendered, list) else [rendered]
    return [v for v in values if isinstance(v, str) and v]


_WORDCHAR = r"[^\W_]"      # a Unicode letter or digit (underscore is a separator)


def is_word(token: str) -> bool:
    """A single word: letters and digits only (name components, most IDs)."""
    return token.isalnum()


def token_pattern(token: str) -> str:
    """
    Regex for one needle (already upper-case).

    * A single word (letters/digits only: a name component such as "ANN",
      an ID such as "MRN001" or "1234", a date) matches only as a whole
      word, i.e. not run into other letters or digits. So "ANN" is not found
      in "SCANNER", "ZED" not in "ANONYMIZED", "1234" not in a hex hash;
      "DOE" is still found in "Doe_Jane/", "follow-up doe" and "DOE^JANE".
    * Anything else (a full name with "^", an institution with spaces, a
      UID with dots) is a plain substring.
    """
    if is_word(token):
        return rf"(?<!{_WORDCHAR}){re.escape(token)}(?!{_WORDCHAR})"
    return re.escape(token)


def token_in(token: str, hay_upper: str) -> bool:
    if is_word(token):
        return re.search(token_pattern(token), hay_upper) is not None
    return token in hay_upper


def unscanned_binary(ds: Dataset, prefix: str = "") -> list[str]:
    """Element paths of binary elements the leak scan does not search
    (standard OB/OW/OF/OD/OL/OV), recursing. The top-level PixelData is
    excluded because it has its own check; nested PixelData (an icon
    thumbnail, which can carry burned-in text) is reported."""
    out = []
    for elem in ds:
        name = element_name(elem)
        if elem.VR == "SQ":
            for i, item in enumerate(elem.value or []):
                out.extend(unscanned_binary(item, f"{prefix}{name}[{i}]."))
        elif (elem.VR in BINARY_VRS and not (elem.tag == 0x7FE00010 and not prefix)
              and not is_scanned_binary(elem) and elem.value):
            out.append(prefix + name)
    return out


def find_residual_phi(deidentified: Dataset, needles: dict[str, str],
                      acknowledged: frozenset[str], prefix: str = "",
                      uids: Optional[dict[str, str]] = None) -> list[dict]:
    """
    Search every element of a de-identified dataset (recursing into
    sequences, including private and UN elements) for values from the
    identified header.

    needles: {UPPERCASE text token: source keyword} -- substring match in
             text elements.
    uids:    {original UID: source keyword} -- exact match in UI elements,
             substring match in text elements.

    Elements named in `acknowledged` are skipped (intentionally retained).
    PixelData is never searched.
    """
    hits: list[dict] = []
    uids = uids or {}
    if not needles and not uids:
        return hits
    for elem in deidentified:
        if elem.tag == 0x7FE00010:
            continue
        name = element_name(elem)
        path = prefix + name
        if elem.VR == "SQ":
            for i, item in enumerate(elem.value or []):
                hits.extend(find_residual_phi(item, needles, acknowledged, f"{path}[{i}].", uids))
            continue
        if name in acknowledged:
            continue
        for v in _text_values(elem):
            if elem.VR == "UI":
                v = v.rstrip("\x00 ")
                if v in uids:
                    hits.append({"path": path, "keyword": name, "kind": "uid",
                                 "source_keyword": uids[v], "matched": v})
                continue
            hay = v.upper()
            for token, source in needles.items():
                if token_in(token, hay):
                    hits.append({"path": path, "keyword": name, "kind": "text",
                                 "source_keyword": source, "matched": token})
            for uid, source in uids.items():
                if uid in v:
                    hits.append({"path": path, "keyword": name, "kind": "uid",
                                 "source_keyword": source, "matched": uid})
    return hits


def find_residual_phi_in_file(deidentified: pydicom.dataset.FileDataset,
                              identified: pydicom.dataset.FileDataset,
                              min_len: int, acknowledged: frozenset[str]) -> list[dict]:
    """Residual-PHI scan of one de-identified file (File Meta + dataset)
    against the values of its own identified counterpart."""
    needles = phi_needles(identified, min_len)
    uids = uid_needles(identified)
    hits = []
    meta = getattr(deidentified, "file_meta", None)
    if meta is not None:
        hits.extend(find_residual_phi(meta, needles, acknowledged, "file_meta.", uids))
    hits.extend(find_residual_phi(deidentified, needles, acknowledged, "", uids))
    return hits


class NeedleIndex:
    """
    Every identifying token seen across the whole run, for scanning things
    that do not belong to one file pair: relative paths of the anonymized
    tree and non-DICOM files in it. One compiled alternation, longest token
    first, so a large run stays fast.
    """

    def __init__(self):
        self.tokens: dict[str, str] = {}
        self._rx = None

    def add(self, needles: dict[str, str]):
        for t, src in needles.items():
            if t not in self.tokens:
                self.tokens[t] = src
                self._rx = None

    def __len__(self):
        return len(self.tokens)

    def search(self, text: str) -> list[tuple[str, str]]:
        """[(matched token, source keyword)], distinct, case-insensitive."""
        if not self.tokens or not text:
            return []
        if self._rx is None:
            alts = sorted(self.tokens, key=len, reverse=True)
            self._rx = re.compile("|".join(token_pattern(a) for a in alts))
        found = dict.fromkeys(m.group(0) for m in self._rx.finditer(text.upper()))
        return [(t, self.tokens[t]) for t in found]


# --------------------------------------------------------------------------
# Pixel checks
# --------------------------------------------------------------------------

def pixel_digest(ds: Dataset) -> Optional[str]:
    elem = ds.get(0x7FE00010)
    if elem is None or elem.value is None:
        return None
    return sha256_hex(bytes(elem.value))


#: pixel_integrity outcomes that are integrity errors.
PIXEL_ERRORS = frozenset({"mismatch", "absent_in_anonymized", "absent_in_original"})


def pixel_integrity(original: Dataset, anonymized: Dataset, compare: bool = True) -> str:
    """
    match | mismatch | absent_both | absent_in_original | absent_in_anonymized
    | not_compared. Presence is always checked; compare=False skips only the
    byte-for-byte comparison (--skipPixelCheck).
    """
    has_a, has_b = 0x7FE00010 in original, 0x7FE00010 in anonymized
    if not has_a and not has_b:
        return "absent_both"
    if not has_a:
        return "absent_in_original"
    if not has_b:
        return "absent_in_anonymized"
    if not compare:
        return "not_compared"
    return "match" if pixel_digest(original) == pixel_digest(anonymized) else "mismatch"


def read_redaction_sidecar(identified_path: Path) -> dict:
    """
    pl-dicom_pixel_redact --save-bboxes writes Presidio's bounding-box list
    next to each output DICOM as <stem>.json: [{entity_type, score, left,
    top, width, height}, ...]. No sidecar does NOT mean no redaction.
    """
    sidecar = identified_path.with_suffix(".json")
    if not sidecar.is_file():
        return {"status": "no_sidecar", "boxes": 0, "entity_types": {}}
    try:
        boxes = json.loads(sidecar.read_text())
        if not isinstance(boxes, list):
            raise ValueError("sidecar is not a list")
    except Exception:  # noqa: BLE001
        return {"status": "unreadable_sidecar", "boxes": 0, "entity_types": {}}
    types = Counter(str(b.get("entity_type", "UNKNOWN")) for b in boxes if isinstance(b, dict))
    scores = [b.get("score") for b in boxes if isinstance(b, dict) and isinstance(b.get("score"), (int, float))]
    return {
        "status": "redacted" if boxes else "no_detections",
        "boxes": len(boxes),
        "entity_types": dict(sorted(types.items())),
        "max_score": max(scores) if scores else None,
        "min_score": min(scores) if scores else None,
    }


# --------------------------------------------------------------------------
# Crosswalk accumulation
# --------------------------------------------------------------------------

def _top(ds: Dataset, kw: str) -> str:
    elem = get_elem(ds, kw)
    if elem is None or elem.value is None:
        return ""
    v = render(elem)
    return "\\".join(v) if isinstance(v, list) else (v if isinstance(v, str) else "")


@dataclass
class PatientRecord:
    original_names: set = field(default_factory=set)
    new_ids: set = field(default_factory=set)
    new_names: set = field(default_factory=set)
    studies: set = field(default_factory=set)
    files: int = 0
    date_actions: Counter = field(default_factory=Counter)
    date_deltas: Counter = field(default_factory=Counter)


class Crosswalk:
    def __init__(self):
        self.patients: dict[str, PatientRecord] = defaultdict(PatientRecord)
        self.accessions: dict[str, dict] = {}
        self.uid_fwd: dict[str, set] = defaultdict(set)
        self.uid_rev: dict[str, set] = defaultdict(set)
        self.uid_level: dict[str, set] = defaultdict(set)
        self.uid_refs: Counter = Counter()
        self.broken_references: Counter = Counter()
        self.dates: list[dict] = []
        self.date_actions: Counter = Counter()

    @staticmethod
    def patient_key(ds: Dataset) -> str:
        pid = _top(ds, "PatientID")
        return pid if pid else f"<no PatientID; name={_top(ds, 'PatientName')}>"

    def add_file(self, rel: str, identified: Dataset, deidentified: Dataset, changes: list[Change]):
        key = self.patient_key(identified)
        p = self.patients[key]
        p.files += 1
        p.original_names.add(_top(identified, "PatientName"))
        p.new_ids.add(_top(deidentified, "PatientID"))
        p.new_names.add(_top(deidentified, "PatientName"))
        study = _top(identified, "StudyInstanceUID")
        if study:
            p.studies.add(study)

        acc = _top(identified, "AccessionNumber")
        if acc:
            rec = self.accessions.setdefault(acc, {"new": set(), "patients": set(), "studies": set()})
            rec["new"].add(_top(deidentified, "AccessionNumber"))
            rec["patients"].add(key)
            if study:
                rec["studies"].add(study)

        for c in changes:
            if (c.vr == "UI" and c.action in ("emptied", "removed")
                    and c.keyword.startswith("Referenced") and not is_empty(c.original)):
                self.broken_references[c.keyword] += 1
            if c.vr == "UI" and c.action == "replaced":
                o, n = first_str(c.original), first_str(c.new)
                if o and n:
                    self.uid_fwd[o].add(n)
                    self.uid_rev[n].add(o)
                    self.uid_level[o].add(UID_LEVELS.get(c.keyword, "other"))
                    self.uid_refs[o] += 1
            if c.vr in DATE_VRS and c.action in ("removed", "emptied", "replaced", "retained"):
                action, delta = classify_date(c)
                p.date_actions[action] += 1
                self.date_actions[action] += 1
                if action == "shifted" and delta is not None:
                    p.date_deltas[delta] += 1
                self.dates.append({
                    "patient_key": key, "file": rel, "element": c.path, "vr": c.vr,
                    "original": first_str(c.original) if c.original is not None else "",
                    "new": first_str(c.new) if c.new is not None else "",
                    "action": action, "delta_days": "" if delta is None else delta,
                })

    # -- derived views -------------------------------------------------------

    def patient_date_handling(self, p: PatientRecord) -> tuple[str, Optional[int], bool]:
        """(description, offset_days or None, offset_consistent)"""
        if p.date_deltas:
            if len(p.date_deltas) == 1:
                offset = next(iter(p.date_deltas))
                return f"shifted {offset:+d} days", offset, True
            return "shifted, inconsistent offsets", None, False
        if not p.date_actions:
            return "no dates present", None, True
        return ";".join(f"{k}={v}" for k, v in sorted(p.date_actions.items())), None, True

    def uid_conflicts(self) -> tuple[list[str], list[str]]:
        one_to_many = sorted(o for o, ns in self.uid_fwd.items() if len(ns) > 1)
        many_to_one = sorted(n for n, os_ in self.uid_rev.items() if len(os_) > 1)
        return one_to_many, many_to_one

    def pseudonym_findings(self) -> tuple[list[str], list[str]]:
        inconsistent = sorted(k for k, p in self.patients.items() if len(p.new_ids) > 1)
        owners = defaultdict(set)
        for k, p in self.patients.items():
            for nid in p.new_ids:
                if nid:
                    owners[nid].add(k)
        collisions = sorted(n for n, ks in owners.items() if len(ks) > 1)
        return inconsistent, collisions

    # -- writers -------------------------------------------------------------

    def rows_patients(self) -> Iterable[dict]:
        for key in sorted(self.patients):
            p = self.patients[key]
            handling, offset, consistent = self.patient_date_handling(p)
            yield {
                "original_patient_id": key,
                "original_patient_name": "|".join(sorted(p.original_names)),
                "anonymized_patient_id": "|".join(sorted(p.new_ids)),
                "anonymized_patient_name": "|".join(sorted(p.new_names)),
                "pseudonym_consistent": len(p.new_ids) <= 1,
                "date_handling": handling,
                "date_offset_days": "" if offset is None else offset,
                "date_offset_consistent": consistent,
                "n_studies": len(p.studies),
                "n_files": p.files,
            }

    def rows_accessions(self) -> Iterable[dict]:
        for acc in sorted(self.accessions):
            r = self.accessions[acc]
            yield {
                "original_accession_number": acc,
                "anonymized_accession_number": "|".join(sorted(r["new"])),
                "original_patient_id": "|".join(sorted(r["patients"])),
                "original_study_instance_uid": "|".join(sorted(r["studies"])),
                "consistent": len(r["new"]) <= 1,
            }

    def rows_uids(self) -> Iterable[dict]:
        order = {"study": 0, "series": 1, "sop": 2, "frame_of_reference": 3, "other": 4}
        def level(o):
            lv = self.uid_level[o]
            return min(lv, key=lambda x: order.get(x, 9)) if lv else "other"
        for o in sorted(self.uid_fwd, key=lambda u: (order.get(level(u), 9), u)):
            yield {
                "level": level(o),
                "original_uid": o,
                "anonymized_uid": "|".join(sorted(self.uid_fwd[o])),
                "occurrences": self.uid_refs[o],
                "consistent": len(self.uid_fwd[o]) == 1,
            }
