"""Survey authorized labs for protocols that are actually configured.

Differential testing is only meaningful where a protocol exists. A lab whose
routers are still `administratively down` cannot confirm or refute an STP, NAT or
IPv6 prediction, so this survey records which protocols each lab genuinely carries
before any comparison is attempted. Read-only: one disposable copy per lab.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from trident.simulator import SimulatorRuntime

LABS = [
    "test-labs/incoming/CCNA 3 Practice PTSA.pka",
    "test-labs/incoming/CCNA Mega Lab (Jeremy's IT Lab)(1).pka",
    "test-labs/incoming/Final_R3_BDSM.pka",
    "test-labs/incoming/Modules_1-13_Image.pka",
    "test-labs/incoming/R3_OKCUP_24_25_CiscoPT(1).pka",
]

SURVEY = [
    ("config", "show running-config"),
    ("acl", "show access-lists"),
    ("nat", "show ip nat translations"),
    ("ipv6", "show ipv6 route"),
    ("stp", "show spanning-tree summary"),
    ("eth", "show etherchannel summary"),
    ("l3", "show ip interface brief"),
]


def survey_lab(runtime: SimulatorRuntime, lab: Path, max_devices: int = 12) -> dict:
    out: dict = {
        "lab": lab.name,
        "exists": lab.is_file(),
        "size_bytes": lab.stat().st_size if lab.is_file() else 0,
        "devices": [],
        "cli_capable": [],
        "findings": {},
        "error": None,
    }
    if not lab.is_file():
        out["error"] = "missing"
        return out

    try:
        session = runtime.create_session(lab)
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"[:300]
        return out

    try:
        names = [str(d.get("name", "")).strip() for d in session.backend.devices()]
        out["devices"] = [n for n in names if n]

        for name in out["devices"][:max_devices]:
            try:
                probe = session.run_cli(name, "show version", timeout=25)
            except Exception:
                continue
            if not (probe.ok and probe.raw):
                continue
            out["cli_capable"].append(name)
            for key, command in SURVEY:
                try:
                    res = session.run_cli(name, command, timeout=25)
                except Exception as exc:
                    out["findings"].setdefault(key, {}).setdefault(name, {})[
                        "error"
                    ] = f"{type(exc).__name__}"[:80]
                    continue
                text = res.raw or ""
                out["findings"].setdefault(key, {})[name] = {
                    "ok": bool(res.ok),
                    "observed": bool(res.observed),
                    "chars": len(text),
                    "lines": len([ln for ln in text.splitlines() if ln.strip()]),
                    "head": "\n".join(text.splitlines()[:6]),
                }
    finally:
        try:
            session.close()
        except Exception:
            pass
    return out


def main() -> int:
    runtime = SimulatorRuntime(prefer_live=True)
    results = [survey_lab(runtime, Path(lab)) for lab in LABS]
    Path("docs/oracle/evidence/lab_survey.json").write_text(
        json.dumps(results, indent=2) + "\n", encoding="utf-8"
    )
    for r in results:
        cli = len(r["cli_capable"])
        print(f"{r['lab'][:42]:44s} size={r['size_bytes']:>9d} cli={cli:>2d} "
              f"err={str(r['error'])[:40] or '-'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
