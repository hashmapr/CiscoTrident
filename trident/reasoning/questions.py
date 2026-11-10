"""Question parsing: split a pasted block into numbered questions.

Supported shapes (all seen in real assessment pastes):

    1. Question text?
       A. option one
       B. option two

    1) Multi-select question? (Choose two.)
    A) alpha
    B) beta

    Q3: True or false: ...
    True / False

    4. Open-ended: describe OSPF area types.

    Question 5
    A. ...

The parser is deliberately conservative: it preserves the original numbering and
the original option letters, and it never invents questions.
"""

from __future__ import annotations

import re

from ..models import ParsedQuestion, QuestionKind, QuestionOption

_NUM_RE = re.compile(
    r"^\s*(?:question\s+|q\s*)?(\d{1,3})\s*[\.\)\:\-]\s*(.*)$",
    re.IGNORECASE,
)
_OPTION_RE = re.compile(r"^\s*([A-Ha-h])\s*[\.\)\:]\s+(.*)$")
_BARE_OPTION_RE = re.compile(r"^\s*([A-Ha-h])\)\s*(.*)$")
_TRUE_FALSE_RE = re.compile(r"^\s*(true|false)\s*$", re.IGNORECASE)
_MULTI_HINT_RE = re.compile(
    r"(choose\s+(two|three|four|all)|select\s+(two|three|all)|choose\s+all|select\s+all|"
    r"choose\s+two\s+answers|more\s+than\s+one)",
    re.IGNORECASE,
)
_YES_NO_RE = re.compile(r"\b(true\s+or\s+false|true/false)\b", re.IGNORECASE)


class QuestionParseError(ValueError):
    pass


def parse_questions(
    text: str,
    fallback_start: int = 1,
    max_questions: int = 500,
    max_chars: int = 8000,
) -> list[ParsedQuestion]:
    """Parse a pasted question block into structured questions."""
    if not text or not text.strip():
        raise QuestionParseError("no questions provided")

    if len(text) > max_questions * max_chars:
        raise QuestionParseError(
            f"question block exceeds the maximum of {max_questions} questions × {max_chars} chars"
        )

    raw_lines = [ln.rstrip() for ln in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]

    # Unnumbered, one-question-per-line input.
    #
    # The block parser below splits only on numbered lines ("1.", "2)"), so a
    # user pasting three bare questions on three lines got ONE merged question —
    # and therefore one answer covering all three. That is the shape people
    # actually paste, so it is handled explicitly.
    #
    # The rule is deliberately narrow: apply it only when there is no numbering
    # at all AND every non-empty line is a standalone question (ends with "?").
    # A multi-line question with options, or any numbered list, keeps the
    # existing block behaviour.
    non_empty = [line.strip() for line in raw_lines if line.strip()]
    unnumbered_list = (
        non_empty
        and not any(_NUM_RE.match(line) for line in non_empty)
        and all(line.rstrip().endswith("?") for line in non_empty)
    )
    if unnumbered_list:
        questions: list[ParsedQuestion] = []
        for index, line in enumerate(non_empty):
            stem = line[:max_chars] if len(line) > max_chars else line
            questions.append(_classify(fallback_start + index, stem))
        if len(questions) > max_questions:
            raise QuestionParseError(
                f"too many questions ({len(questions)} > {max_questions})"
            )
        return questions

    blocks: list[tuple[int | None, list[str]]] = []
    current_number: int | None = None
    current_lines: list[str] = []

    for line in raw_lines:
        if not line.strip():
            if current_lines:
                current_lines.append("")
            continue
        m = _NUM_RE.match(line)
        if m:
            new_num = int(m.group(1))
            # Any numbered line starts a new question. Requiring the numbering to
            # advance dropped every question after an out-of-order or duplicate
            # number (e.g. a pasted excerpt starting at 65 then 57, 54), silently
            # losing most of the batch.
            if current_lines:
                blocks.append((current_number, current_lines))
            current_number, current_lines = new_num, [m.group(2)]
            continue

        if current_number is None:
            current_number = fallback_start
        current_lines.append(line)

    if current_lines:
        blocks.append((current_number, current_lines))

    if not blocks:
        raise QuestionParseError("could not identify any questions in the input")

    questions: list[ParsedQuestion] = []
    for idx, (number, lines) in enumerate(blocks):
        qnum = number if number is not None else fallback_start + idx
        text_block = "\n".join(lines).strip()
        if not text_block:
            continue
        if len(text_block) > max_chars:
            text_block = text_block[:max_chars]
        questions.append(_classify(qnum, text_block))

    if not questions:
        raise QuestionParseError("no non-empty questions found")
    if len(questions) > max_questions:
        raise QuestionParseError(f"too many questions ({len(questions)} > {max_questions})")
    return questions


def _classify(number: int, original: str) -> ParsedQuestion:
    lines = original.split("\n")
    stem_lines: list[str] = []
    options: list[QuestionOption] = []

    for line in lines:
        m = _OPTION_RE.match(line) or _BARE_OPTION_RE.match(line)
        if m:
            options.append(QuestionOption(letter=m.group(1).upper(), text=m.group(2).strip()))
            continue
        if options:
            # continuation of the last option
            options[-1].text = f"{options[-1].text} {line.strip()}".strip()
        else:
            stem_lines.append(line)

    # bare true/false without letters
    if not options:
        tail = [l.strip() for l in lines if l.strip()]
        if tail and _TRUE_FALSE_RE.match(tail[-1]) and _YES_NO_RE.search(original):
            options = [
                QuestionOption(letter="A", text="True"),
                QuestionOption(letter="B", text="False"),
            ]
            stem_lines = stem_lines[:-1] if len(stem_lines) > 1 else stem_lines

    stem = " ".join(l.strip() for l in stem_lines if l.strip()).strip()
    if not stem:
        stem = original.strip()

    kind = _detect_kind(stem, options)
    return ParsedQuestion(
        question_number=number,
        original=original.strip(),
        kind=kind,
        stem=stem,
        options=options,
    )


def _detect_kind(stem: str, options: list[QuestionOption]) -> QuestionKind:
    if options:
        labels = {o.text.strip().lower() for o in options}
        if labels == {"true", "false"}:
            return QuestionKind.TRUE_FALSE
        if _MULTI_HINT_RE.search(stem):
            return QuestionKind.MULTI_SELECT
        return QuestionKind.SINGLE_SELECT
    if _MULTI_HINT_RE.search(stem):
        return QuestionKind.MULTI_SELECT
    if _YES_NO_RE.search(stem):
        return QuestionKind.TRUE_FALSE
    if re.search(r"\b(why|explain|describe|how does|reason|justify)\b", stem, re.IGNORECASE):
        return QuestionKind.REASONING
    return QuestionKind.FACTUAL
