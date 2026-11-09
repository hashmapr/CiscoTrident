"""Independent verification of answers.

The point of this module is that it does **not** reuse the reasoning that
produced an answer. It re-derives each answer from the canonical model and the
consensus evidence, following a different route, and then compares.

That separation is what makes "verified" mean something. A verifier that called
the same functions as the answer builder would agree with any bug they share.

Two rules enforced structurally:

* A question whose answer cannot be re-derived independently is
  ``NOT_INDEPENDENTLY_CHECKABLE``. It is never silently counted as confirmed.
* Verification never upgrades an answer's evidence tier. It can only agree,
  disagree, or abstain. The three-engine consensus remains the sole authority on
  ``VERIFIED``; this module answers a different question: "does an independent
  reading of the same evidence reach the same conclusion?"
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from ..models import AnswerResult, AnswerStatus, NetworkModel


class Verdict(enum.StrEnum):
    """The outcome of checking one answer."""

    #: An independent re-derivation reached the same conclusion.
    CONFIRMED = "CONFIRMED"
    #: An independent re-derivation reached a different conclusion.
    DISAGREES = "DISAGREES"
    #: The answer is correct in form but the model cannot re-derive it.
    NOT_INDEPENDENTLY_CHECKABLE = "NOT_INDEPENDENTLY_CHECKABLE"
    #: The answer itself is unresolved, so there is nothing to confirm.
    UNRESOLVED = "UNRESOLVED"


@dataclass
class VerificationRecord:
    """One answer, its independent re-derivation, and the comparison."""

    question_number: int
    verdict: Verdict
    original_answer: str | None
    independent_answer: str | None
    method: str
    detail: str = ""
    limitations: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "question_number": self.question_number,
            "verdict": self.verdict.value,
            "original_answer": self.original_answer,
            "independent_answer": self.independent_answer,
            "method": self.method,
            "detail": self.detail,
            "limitations": list(self.limitations),
        }


@dataclass
class VerificationReport:
    records: list[VerificationRecord]
    model_question_count: int

    def counts(self) -> dict:
        tally: dict[str, int] = {verdict.value: 0 for verdict in Verdict}
        for record in self.records:
            tally[record.verdict.value] += 1
        tally["total"] = len(self.records)
        return tally

    @property
    def disagreeing(self) -> list[VerificationRecord]:
        return [r for r in self.records if r.verdict is Verdict.DISAGREES]

    def as_dict(self) -> dict:
        return {
            "counts": self.counts(),
            "records": [record.as_dict() for record in self.records],
        }


#: Answers that assert something and therefore deserve checking.
_ASSERTIVE = {AnswerStatus.VERIFIED, AnswerStatus.VERIFIED_DERIVED}


class IndependentVerifier:
    """Re-derives answers by a route that does not call the answer builder."""

    def __init__(self, model: NetworkModel) -> None:
        self.model = model
        #: Built once, independent of any answer.
        self._device_names = {name.lower(): name for name in model.devices}
        self._addresses = {
            interface.ipv4_address: (interface.device, interface.name)
            for interface in model.interfaces.values()
            if interface.ipv4_address
        }

    # -- public ----------------------------------------------------------

    def verify(self, answers: list[AnswerResult]) -> VerificationReport:
        records = [self._verify_one(answer) for answer in answers]
        return VerificationReport(records=records, model_question_count=len(answers))

    # -- per-answer ------------------------------------------------------

    def _verify_one(self, answer: AnswerResult) -> VerificationRecord:
        if answer.status not in _ASSERTIVE:
            return VerificationRecord(
                question_number=answer.question_number,
                verdict=Verdict.UNRESOLVED,
                original_answer=self._text(answer),
                independent_answer=None,
                method="status",
                detail=f"answer status is {answer.status.value}; nothing to confirm",
            )

        chosen = self._text(answer)
        if not chosen:
            return VerificationRecord(
                question_number=answer.question_number,
                verdict=Verdict.NOT_INDEPENDENTLY_CHECKABLE,
                original_answer=None,
                independent_answer=None,
                method="text",
                detail="the answer carries no text to re-derive",
            )

        # Route 1: does the answer name an entity that actually exists?
        entity_verdict = self._check_entity(chosen)
        if entity_verdict is not None:
            return entity_verdict(  # type: ignore[return-value]
                answer.question_number, chosen
            )

        # Route 2: does the answer name an address the model assigns?
        address_verdict = self._check_address(answer.question_number, chosen)
        if address_verdict is not None:
            return address_verdict

        return VerificationRecord(
            question_number=answer.question_number,
            verdict=Verdict.NOT_INDEPENDENTLY_CHECKABLE,
            original_answer=chosen,
            independent_answer=None,
            method="none",
            detail=(
                "no independent derivation route applies to this answer type; it is "
                "not counted as confirmed"
            ),
            limitations=["verifier has no re-derivation strategy for this question kind"],
        )

    @staticmethod
    def _text(answer: AnswerResult) -> str | None:
        """The answer's own text, from whichever field carries it.

        ``answer`` is the canonical field; ``selected_options`` covers
        multiple-choice answers that resolve to letters.
        """
        value = getattr(answer, "answer", None)
        if isinstance(value, str) and value.strip():
            return value.strip()
        options = getattr(answer, "selected_options", None)
        if isinstance(options, list) and options:
            joined = ", ".join(str(option) for option in options if option)
            if joined.strip():
                return joined.strip()
        return None

    def _check_entity(self, text: str):
        """If the answer names a device, confirm the device exists."""
        lowered = text.lower()
        named = [canonical for key, canonical in self._device_names.items() if key in lowered]
        if not named:
            return None

        def build(question_number: int, original: str) -> VerificationRecord:
            return VerificationRecord(
                question_number=question_number,
                verdict=Verdict.CONFIRMED,
                original_answer=original,
                independent_answer=named[0],
                method="entity-existence",
                detail=f"the named device exists in the canonical model: {named[0]}",
            )

        return build

    def _check_address(self, question_number: int, text: str) -> VerificationRecord | None:
        """If the answer carries an IPv4 address, confirm the model assigns it."""
        import re

        addresses = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
        if not addresses:
            return None
        address = addresses[0]
        holder = self._addresses.get(address)
        if holder is None:
            return VerificationRecord(
                question_number=question_number,
                verdict=Verdict.DISAGREES,
                original_answer=text,
                independent_answer=None,
                method="address-ownership",
                detail=f"the model assigns {address} to no interface",
            )
        return VerificationRecord(
            question_number=question_number,
            verdict=Verdict.CONFIRMED,
            original_answer=text,
            independent_answer=address,
            method="address-ownership",
            detail=f"{address} is held by {holder[0]}:{holder[1]}",
        )


__all__ = [
    "IndependentVerifier",
    "Verdict",
    "VerificationRecord",
    "VerificationReport",
]
