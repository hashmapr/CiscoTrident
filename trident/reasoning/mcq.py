"""Multiple-choice evaluation.

Rules (strict, no guessing):

* An option matches only when its text is *equivalent* to a verified value after
  normalisation (IP, MAC, interface alias, VLAN id, numeric, or exact phrase).
* If no offered option matches, the result is CONFLICT — never "closest option".
* For multi-select, every correct value must map to exactly one offered option.
"""

from __future__ import annotations

import re

from ..models import AnswerStatus, ParsedQuestion, QuestionOption
from ..normalization.values import (
    canonical_interface_name,
    normalize_ipv4,
    normalize_mac,
)

_LEADING_NOISE_RE = re.compile(r"^(?:answer\s*[:\-]?\s*|option\s+)", re.IGNORECASE)


def _norm_text(value: str) -> str:
    cleaned = _LEADING_NOISE_RE.sub("", value.strip())
    cleaned = cleaned.strip().strip('"').strip("'")
    return " ".join(cleaned.lower().split()).rstrip(".!,;:")


def option_matches_value(option_text: str, value: str) -> bool:
    """True when an option's text is equivalent to an established value."""
    if not option_text or not value:
        return False
    opt = _norm_text(option_text)
    val = _norm_text(value)
    if not opt or not val:
        return False
    if opt == val:
        return True

    a_ip, b_ip = normalize_ipv4(option_text), normalize_ipv4(value)
    if a_ip and b_ip:
        return a_ip == b_ip

    a_mac, b_mac = normalize_mac(option_text), normalize_mac(value)
    if a_mac and b_mac:
        return a_mac == b_mac

    if re.fullmatch(r"[A-Za-z][A-Za-z\-]*\s*\d[\d/\.\:]*", option_text.strip()) and (
        canonical_interface_name(option_text) == canonical_interface_name(value)
    ):
        return True

    if re.fullmatch(r"\d+", opt) and re.fullmatch(r"\d+", val):
        return int(opt) == int(val)

    # prose answers may quote the established value
    return len(val) >= 4 and val in opt


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
        ("None of the offered options matches the verified value; "
         "the question may be inconsistent with the supplied network file."),
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
        return (
            AnswerStatus.INCOMPLETE,
            sorted(selected),
            "Some established facts have no matching offered option: " + "; ".join(unmatched_values),
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
