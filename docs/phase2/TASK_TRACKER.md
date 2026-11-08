# TaskTracker — Phase 2

Presentation layer over one practice-lab assessment: turns a
`LabAssessment` into a per-instruction board a learner can work from.

```
instructions ──► build_board(model, instructions) ──► TaskBoard
                                                         │
                                model change ──► reassess(board, model, instructions)
```

The tracker **adds no evaluation logic**. `build_board` calls
`trident.workflow.assess_lab`, which calls `trident.compliance.evaluate`. The
tracker only decides bookkeeping: one entry per instruction line, a `task_id`
that survives a reassessment, and a progress denominator built from *evaluable*
tasks. Read-only: nothing here writes a file, opens a socket, or runs a command.

## Public API

```python
from trident.tracker import (
    EVALUABLE_STATES, STATE_ORDER,
    TaskBoard, TaskEntry, TaskState,
    build_board, reassess, state_from_status,
)

def build_board(
    model: NetworkModel,
    instructions: str,
    *,
    lab_title: str = "Practice lab",
    generate_remediation: bool = True,
) -> TaskBoard: ...

def reassess(board: TaskBoard, model: NetworkModel, instructions: str) -> TaskBoard: ...
```

### `TaskState`

| State | Meaning |
| --- | --- |
| `SATISFIED` | The snapshot meets the instruction, with evidence. |
| `UNSATISFIED` | The snapshot records a value that contradicts it. |
| `PARTIALLY_SATISFIED` | Some of the obligation holds (e.g. right address, wrong prefix). |
| `INDETERMINATE` | The snapshot cannot support a verdict either way. |
| `UNSUPPORTED` | The snapshot cannot speak to the referenced device/interface. |
| `NOT_EVALUATED` | **Tracker only.** The line never became a testable requirement (unparsed, or no evaluator for its kind). |

`NOT_EVALUATED` is distinct from both `UNSATISFIED` and `UNSUPPORTED`. It says
nothing about the network; it says the *instruction* could not be tested.

### `TaskEntry`

```python
@dataclass(frozen=True, slots=True)
class TaskEntry:
    task_id: str                # TASK-<sha256(kind \0 text \0 occurrence)[:12]>
    requirement_id: str         # the parser's id, REQ-0007
    text: str                   # the lab instruction as written
    kind: str                   # RequirementKind value, e.g. "ipv4_address"
    device: str | None
    state: TaskState
    evidence: tuple[str, ...]   # "detail [source]" per compliance Evidence
    remediation_available: bool # a workflow plan exists; it is still advice only
    rechecked_from: str | None  # previous state on reassessment, None on first build
```

`evidence` is never empty for a `SATISFIED` entry — the tracker re-applies the
compliance engine's invariant and downgrades an evidence-less `SATISFIED` to
`INDETERMINATE`. For a `NOT_EVALUATED` entry the tuple holds the single reason,
prefixed `"not evaluated: "`, so the instruction is preserved with its reason
rather than dropped.

`device` prefers the resolved model key from the compliance result, falling back
to the parser's `device` (which may be `None` for group-scoped instructions).

### `TaskBoard`

```python
@dataclass
class TaskBoard:
    lab_title: str
    snapshot_id: str
    entries: list[TaskEntry]

    def summary(self) -> dict[str, int]        # counts by state, all six keys always present
    def outstanding(self) -> list[TaskEntry]    # everything not SATISFIED
    def evaluable(self) -> list[TaskEntry]      # entries in EVALUABLE_STATES
    def progress_pct(self) -> float
    def to_dict(self) -> dict
```

## Progress arithmetic

`progress_pct()` is `100 * satisfied / evaluable`, where

```python
EVALUABLE_STATES = {SATISFIED, UNSATISFIED, PARTIALLY_SATISFIED, INDETERMINATE}
```

**The denominator is the number of evaluable tasks, not all tasks.** This is the
point of the metric: an unparseable or unevaluable instruction must not move
progress in either direction.

* Excluded from the denominator: `UNSUPPORTED`, `NOT_EVALUATED`.
* In the denominator but not the numerator: `UNSATISFIED`, `PARTIALLY_SATISFIED`,
  `INDETERMINATE`.
* A board with nothing evaluable returns `0.0` — there is no defensible
  percentage to report.

Worked example — `1 satisfied, 1 unsatisfied, 1 unsupported`:

| Formula | Result | Correct? |
| --- | --- | --- |
| satisfied / evaluable = 1 / 2 | **50.0** | yes |
| satisfied / all = 1 / 3 | 33.3 | no — an unsupported task deflates progress |
| satisfied / (satisfied + unsatisfied) computed from "done" only | 100.0 | no — ignores the failure |

## Reassessment

`reassess(board, model, instructions)` re-runs the assessment and diffs it
against the previous board.

* `task_id` is derived from **instruction text + kind** (plus a duplicate
  occurrence index), never from the line number or the parser's `REQ-nnnn`.
  Inserting or reordering lines therefore does not rewrite every id, so a
  per-task diff between two boards is meaningful.
* `rechecked_from` is set to the previous state for **every** task that existed
  on the previous board, including unchanged ones. A change is simply
  `entry.rechecked_from != entry.state.value`.
* A task seen for the first time has `rechecked_from is None`.
* The previous board's `lab_title` is retained by the new board.

## Guarantees

| Guarantee | Where enforced |
| --- | --- |
| One entry per non-blank instruction line | `build_board` iterates `assessment.outcomes`, one per parsed line |
| Unparseable lines preserved with a reason | `_entry_from` writes `NOT_EVALUATED` + reason into `evidence` |
| `SATISFIED` always has evidence | `_state_for` downgrades to `INDETERMINATE` when `ComplianceResult.evidence` is empty |
| Progress excludes unevaluable tasks | `EVALUABLE_STATES` / `TaskBoard.progress_pct` |
| Stable ids across reassessment | `_task_id(kind, text, occurrence)` |
| No re-implementation of evaluation | `build_board` delegates to `assess_lab` |
| Read-only | no I/O, sockets, or subprocess use anywhere in the package |

## Limitations

* The board is per *instruction document*; it does not merge multiple labs.
* `progress_pct` is a count of tasks, not of configuration complexity — one
  address line and one whole OSPF rollout weigh the same.
* `INDETERMINATE` is evaluable and therefore counts against progress, by
  design: the snapshot was asked and could not confirm the task.
* Duplicate identical instruction lines are kept as separate tasks (with
  distinct ids); collapsing them would hide a real repetition in the sheet.

## Tests

`tests/test_phase2/test_tracker.py` — 23 tests covering one-entry-per-line,
the progress arithmetic (stated as explicit alternative formulas that must not
hold), state flips and `rechecked_from` on reassessment, id stability,
`NOT_EVALUATED` preservation, the evidence invariant, summary summation, and a
`json.dumps` round-trip of `to_dict`.
