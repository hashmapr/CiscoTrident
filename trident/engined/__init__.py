"""Engine D: does this network satisfy its *intended* communication requirements?

The distinction from the existing diagnostics engine is the whole reason this
package exists.

``trident.diagnostics`` asks a weaker question: *is this configuration
internally odd?* It can say "this subnet exists and that router has no route to
it" — a statement about configuration, not about whether the route is required.
That produced a real failure: a detector asking the weaker question reported five
faults on a documented-healthy network, because a router with a correct default
route and an ISP edge router with no private routes both look like gaps.

Engine D asks the question an operator actually cares about:

    given a stated intent — "host A must reach host B" — does the network
    forward traffic that way, and if not, which device decides that?

Two consequences follow, and they are enforced in code rather than documented:

* **A missing route is not a fault by default.** Absence of reachability is only
  reported against a requirement that says the reachability is needed.
* **Segmentation is not a fault either.** A pair declared isolated that cannot
  reach each other is a *pass*.

Engine D is deliberately not a parser and not a vote. It consumes the normalised
model that the parsers already agreed on, and it does not participate in
three-engine consensus. Operational (live simulator) evidence is a *separate*
input that can confirm or contradict a prediction; it never counts as another
parser and never silently upgrades a status.
"""

from .intent import Endpoint, NetworkIntent, Requirement
from .reachability import (
    AclDecision,
    ForwardingTable,
    PathResult,
    decide_forwarding,
    evaluate_acls,
    vlan_path,
)
from .verify import (
    FaultFinding,
    IntentReport,
    RequirementVerdict,
    Status,
    explain,
    verify_intent,
    verify_requirement,
)

__all__ = [
    "AclDecision",
    "Endpoint",
    "FaultFinding",
    "ForwardingTable",
    "IntentReport",
    "NetworkIntent",
    "PathResult",
    "Requirement",
    "RequirementVerdict",
    "Status",
    "decide_forwarding",
    "evaluate_acls",
    "explain",
    "verify_intent",
    "verify_requirement",
    "vlan_path",
]
