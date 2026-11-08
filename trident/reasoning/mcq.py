"""Multiple-choice evaluation — strict, type-aware, no substring guessing.

Rules (strict, no guessing):

* An option matches only when it is *equivalent* to a verified value under a
  type-aware comparison (IPv4, IPv6, mask, CIDR, MAC, interface alias, VLAN id,
  number, boolean, or exact normalised text).
* The old substring fallback (``len(val) >= 4 and val in opt``) is gone: it made
  ``VLAN 10`` match ``VLAN 100`` and let a correct value embedded in a false
  sentence verify the sentence.
* If no offered option matches -> CONFLICT. Never "closest option".
* For multi-select, every offered option is adjudicated TRUE / FALSE / UNKNOWN.
"""

from __future__ import annotations

import re

from ..models import AnswerStatus, ParsedQuestion, QuestionOption
from ..normalization.values import (
    canonical_interface_name,
    is_valid_mask,
    mask_to_prefix,
    normalize_ip,
    normalize_ipv4,
    normalize_mac,
)

_LEADING_NOISE_RE = re.compile(r"^(?:answer\s*[:\-]?\s*|option\s+)", re.IGNORECASE)

_EXPECTED_HINT_RE = re.compile(r"\b(?:choose|select)\s+(two|three|four)\b", re.IGNORECASE)
_HINT_WORD_TO_COUNT = {"two": 2, "three": 3, "four": 4}

#: Words that invert an option's meaning when they qualify a matched value.
_NEGATION_RE = re.compile(
    r"\b(not|no|none|never|cannot|can't|isn't|aren't|doesn't|don't|without|"
    r"except|incorrect|false)\b",
    re.IGNORECASE,
)

_TRUE_WORDS = {"true", "yes", "correct", "on", "enabled", "up"}
_FALSE_WORDS = {"false", "no", "incorrect", "off", "disabled", "down"}


def expected_selections(stem: str) -> int | None:
    """Stated number of choices, e.g. 'choose two' -> 2, or None if unstated."""
    m = _EXPECTED_HINT_RE.search(stem or "")
    if m:
        return _HINT_WORD_TO_COUNT.get(m.group(1).lower())
    return None


def _norm_text(value: str) -> str:
    cleaned = _LEADING_NOISE_RE.sub("", (value or "").strip())
    cleaned = cleaned.strip().strip('"').strip("'")
    return " ".join(cleaned.lower().split()).rstrip(".!;,:?")


def _negated(text: str) -> bool:
    return bool(_NEGATION_RE.search(text or ""))


def _vlan_number(text: str) -> int | None:
    m = re.fullmatch(r"\s*(?:vlan\s*)?(\d{1,4})\s*", text or "", re.IGNORECASE)
    return int(m.group(1)) if m else None


def _number(text: str) -> float | None:
    m = re.fullmatch(r"\s*(-?\d+(?:\.\d+)?)\s*", (text or "").replace(",", ""))
    return float(m.group(1)) if m else None


def _cidr(text: str) -> tuple[str, int] | None:
    m = re.fullmatch(r"\s*(\d{1,3}(?:\.\d{1,3}){3})\s*/\s*(\d{1,2})\s*", text or "")
    if not m:
        return None
    ip = normalize_ipv4(m.group(1))
    prefix = int(m.group(2))
    if ip is None or not 0 <= prefix <= 32:
        return None
    return ip, prefix


def _boolean(text: str) -> bool | None:
    word = _norm_text(text)
    if word in _TRUE_WORDS:
        return True
    if word in _FALSE_WORDS:
        return False
    return None


def _interface_only(text: str) -> str | None:
    """Canonical interface name when the whole option is just an interface."""
    stripped = (text or "").strip()
    if not re.fullmatch(r"[A-Za-z][A-Za-z\-_ ]*\d[\d/\.:]*", stripped):
        return None
    return canonical_interface_name(stripped) or None


def equivalence(option_text: str, value: str) -> str | None:
    """Return the equivalence kind when option == value, else None.

    Kinds: exact | text | ipv4 | ipv6 | cidr | mask | mac | interface | vlan |
    number | boolean. Negation in the option never matches a positive value.
    """
    if not option_text or value is None:
        return None
    opt_raw, val_raw = option_text.strip(), str(value).strip()
    if not opt_raw or not val_raw:
        return None

    # Exact normalised text always wins (and is the only rule for prose).
    if _norm_text(opt_raw) == _norm_text(val_raw):
        return "exact" if opt_raw == val_raw else "text"

    # A negated option may never match a positive established value.
    if _negated(opt_raw) and not _negated(val_raw):
        return None

    # IPv4 / IPv6 (strict: leading zeros and garbage are rejected)
    a_ip, b_ip = normalize_ip(opt_raw), normalize_ip(val_raw)
    if a_ip and b_ip:
        if a_ip != b_ip:
            return None
        return "ipv4" if ":" not in a_ip else "ipv6"

    # CIDR prefix notation
    a_cidr, b_cidr = _cidr(opt_raw), _cidr(val_raw)
    if a_cidr and b_cidr and a_cidr == b_cidr:
        return "cidr"

    # Dotted-decimal mask equivalence (255.255.255.0 == /24)
    if is_valid_mask(opt_raw) and is_valid_mask(val_raw):
        return "mask" if mask_to_prefix(opt_raw) == mask_to_prefix(val_raw) else None

    # MAC address
    a_mac, b_mac = normalize_mac(opt_raw), normalize_mac(val_raw)
    if a_mac and b_mac:
        return "mac" if a_mac == b_mac else None

    # Interface name / alias — only when the option is *only* an interface
    a_if = _interface_only(opt_raw)
    b_if = _interface_only(val_raw)
    if a_if and b_if:
        return "interface" if a_if == b_if else None

    # VLAN identifiers ("VLAN 10" == "10")
    a_vlan, b_vlan = _vlan_number(opt_raw), _vlan_number(val_raw)
    if a_vlan is not None and b_vlan is not None:
        return "vlan" if a_vlan == b_vlan else None

    # Plain numbers (ports, counts, distances)
    a_num, b_num = _number(opt_raw), _number(val_raw)
    if a_num is not None and b_num is not None:
        return "number" if a_num == b_num else None

    # Booleans
    a_bool, b_bool = _boolean(opt_raw), _boolean(val_raw)
    if a_bool is not None and b_bool is not None:
        return "boolean" if a_bool == b_bool else None

    # No substring fallback. Anything else is not equivalent.
    return None


def option_matches_value(option_text: str, value: str) -> bool:
    """True when an option is equivalent to an established value."""
    return equivalence(option_text, value) is not None


def match_single(question: ParsedQuestion, value: str) -> tuple[AnswerStatus, list[str], str]:
    matched = [o.letter for o in question.options if option_matches_value(o.text, value)]
    if len(matched) == 1:
        return AnswerStatus.VERIFIED, matched, f"Option {matched[0]} matches the verified value."
    if len(matched) > 1:
        return (
            AnswerStatus.CONFLICT,
            matched,
            f"Multiple offered options match the verified value: {', '.join(matched)}.",
        )
    return (
        AnswerStatus.CONFLICT,
        [],
        (
            "None of the offered options matches the verified value; "
            "the question may be inconsistent with the supplied network file."
        ),
    )


def match_multi(
    question: ParsedQuestion,
    correct_values: list[str],
    incorrect_values: list[str] | None = None,
) -> tuple[AnswerStatus, list[str], str]:
    incorrect_values = incorrect_values or []
    selected: list[str] = []
    unmatched_values: list[str] = []
    ambiguous: list[str] = []

    for value in correct_values:
        hits = [o.letter for o in question.options if option_matches_value(o.text, value)]
        if len(hits) == 1:
            if hits[0] not in selected:
                selected.append(hits[0])
        elif len(hits) > 1:
            ambiguous.append(f"{value} matched {', '.join(hits)}")
        else:
            unmatched_values.append(value)

    if ambiguous:
        return AnswerStatus.CONFLICT, sorted(selected), f"Ambiguous option mapping: {'; '.join(ambiguous)}."
    if unmatched_values:
        return AnswerStatus.INCOMPLETE, sorted(selected), (
            "Some established facts have no matching offered option: " + "; ".join(unmatched_values)
        )

    for letter in selected:
        opt = next(o for o in question.options if o.letter == letter)
        if any(option_matches_value(opt.text, bad) for bad in incorrect_values):
            return (
                AnswerStatus.CONFLICT,
                sorted(selected),
                f"Option {letter} matches both an established correct and incorrect fact.",
            )

    return AnswerStatus.VERIFIED, sorted(selected), "All established facts matched offered options."


def adjudicate_options(
    question: ParsedQuestion,
    true_values: list[str],
    false_values: list[str] | None = None,
) -> dict[str, str]:
    """Per-option verdict: TRUE (established), FALSE (established untrue), UNKNOWN.

    Every offered option is evaluated independently. An option is TRUE only when
    it is equivalent to an established true value; FALSE only when it is
    equivalent to an established false value; otherwise UNKNOWN.
    """
    false_values = false_values or []
    verdicts: dict[str, str] = {}
    for opt in question.options:
        if any(option_matches_value(opt.text, v) for v in true_values):
            verdicts[opt.letter] = "TRUE"
        elif any(option_matches_value(opt.text, v) for v in false_values):
            verdicts[opt.letter] = "FALSE"
        else:
            verdicts[opt.letter] = "UNKNOWN"
    return verdicts


def match_multi_independent(
    question: ParsedQuestion,
    correct_values: list[str],
    incorrect_values: list[str] | None = None,
) -> tuple[AnswerStatus, list[str], str]:
    """Multi-select where EVERY offered option is adjudicated TRUE/FALSE/UNKNOWN.

    An option is selected only when the evidence establishes it TRUE. A complete
    answer requires every needed option to be TRUE and the stated choice count
    (if any) to be met; otherwise the answer abstains as INCOMPLETE, reporting
    each option's verdict.
    """
    incorrect_values = incorrect_values or []
    per_option: list[str] = []
    selected: list[str] = []
    ambiguous_values: list[str] = []
    unmatched_values: list[str] = []

    for value in correct_values:
        hits = [o.letter for o in question.options if option_matches_value(o.text, value)]
        if len(hits) == 1:
            if hits[0] not in selected:
                selected.append(hits[0])
        elif len(hits) > 1:
            ambiguous_values.append(f"{value} matched {', '.join(hits)}")
        else:
            unmatched_values.append(value)

    if ambiguous_values:
        return AnswerStatus.CONFLICT, sorted(selected), (
            "Ambiguous option mapping: " + "; ".join(ambiguous_values) + "."
        )
    if unmatched_values:
        return AnswerStatus.INCOMPLETE, sorted(selected), (
            "Some established facts have no matching offered option: "
            + "; ".join(unmatched_values)
        )

    verdicts = adjudicate_options(question, correct_values, incorrect_values)

    # A value established as both true and false is a contradiction: never pick.
    contradictions = [
        opt.letter
        for opt in question.options
        if any(option_matches_value(opt.text, v) for v in correct_values)
        and any(option_matches_value(opt.text, v) for v in incorrect_values)
    ]
    if contradictions:
        return AnswerStatus.CONFLICT, sorted(selected), (
            "Option(s) "
            + ", ".join(sorted(contradictions))
            + " match both an established true and an established false fact."
        )

    for opt in question.options:
        per_option.append(f"{opt.letter}={verdicts[opt.letter]}")

    unknown = [letter for letter, verdict in verdicts.items() if verdict == "UNKNOWN"]
    if unknown:
        return AnswerStatus.INCOMPLETE, sorted(selected), (
            "Every offered option must be verifiable for a multi-select answer; "
            "UNKNOWN: "
            + ", ".join(unknown)
            + ". "
            + " ".join(per_option)
        )

    # A selected option that also matches an established-false value is a conflict.
    for letter in selected:
        if verdicts.get(letter) == "FALSE":
            return AnswerStatus.CONFLICT, sorted(selected), (
                f"Option {letter} is established false but was selected. {' '.join(per_option)}"
            )

    expected = expected_selections(question.stem or question.original)
    if expected is not None and len(selected) != expected:
        return AnswerStatus.INCOMPLETE, sorted(selected), (
            f"The question expects {expected} choice(s) but verification established "
            f"{len(selected)}. " + " ".join(per_option)
        )

    return AnswerStatus.VERIFIED, sorted(selected), (
        "Every offered option independently adjudicated. " + " ".join(per_option)
    )


def match_true_false(question: ParsedQuestion, claim_is_true: bool) -> tuple[AnswerStatus, list[str], str]:
    wanted = "true" if claim_is_true else "false"
    hits = [o.letter for o in question.options if _norm_text(o.text) == wanted]
    if len(hits) == 1:
        return AnswerStatus.VERIFIED, hits, f"The established fact makes the statement {wanted}."
    return AnswerStatus.CONFLICT, [], f"No offered option corresponds to '{wanted}'."


def select_by_text(options: list[QuestionOption], text: str) -> str | None:
    target = _norm_text(text)
    for o in options:
        if _norm_text(o.text) == target:
            return o.letter
    return None
