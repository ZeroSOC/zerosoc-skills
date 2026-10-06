#!/usr/bin/env python3
"""Classify a containment action under the autonomy matrix of Incident Response §2.1. Standard library only.

  autonomy.py --action "isolate workstation WS-07" --confidence High --severity High \
              [--preset isolate-workstation] [--reversible yes|no] [--stops-critical-service yes|no] \
              [--irreversible yes|no] [--mass yes|no] [--target NAME] [--target-kind person|service|host] [--json]

Presets set the matrix attributes for the common actions; explicit flags override them. Output: the tier
(pre-authorized / requires approval), the matrix entry that decides it, the timing rule from severity,
and, when approval is required, the five-part presentation payload of Agentic Guardrails §2 to fill in.

An identity action (suspending sessions, disabling an identity) targets a person's account or a service
identity (Incident Response §1). On a host's own identity (the computer account a directory gives a joined
device, an operating system's built-in principal such as SYSTEM) it is **not selected**: the host is
contained instead, by isolating it. `--target-kind` states what the target is; without it the name is read
for what it states (a trailing `$`, a built-in principal). A target not selected exits 1.
"""
import argparse, json, sys

PRESETS = {
    # name: (reversible, stops_critical_service, irreversible, mass)
    "isolate-workstation": (True, False, False, False),
    "isolate-server": (True, True, False, False),
    "isolate-domain-controller": (True, True, False, False),
    "suspend-sessions": (True, False, False, False),
    "disable-user-identity": (True, False, False, False),
    "disable-service-identity": (True, True, False, False),
    "revoke-credential": (True, False, False, False),
    "block-indicator": (True, False, False, False),
    "egress-block": (True, False, False, False),
    "quarantine-file": (True, False, False, False),
    "quarantine-email": (True, False, False, False),
    "purge-email": (False, False, True, False),
    "isolate-subnet": (True, True, False, True),
    "modify-routing": (False, True, False, True),
    "mass-credential-reset": (False, False, False, True),
    "blocklist-partner-network": (True, True, False, True),
    "wipe-reimage-delete": (False, False, True, False),
}


IDENTITY_ACTIONS = ("suspend-sessions", "disable-user-identity", "disable-service-identity")
"""The presets that act on an identity: Incident Response §1 selects them for a person's account or a
service identity only."""
BUILT_IN_PRINCIPALS = ("system", "localsystem", "local service", "network service", "administrators",
                       "users", "everyone", "authenticated users")
"""An operating system's own principals and groups, as a source names them as users."""


def identity_kind(target, stated=None):
    """person / service / host as stated, else "host" where the name itself states it, else None."""
    if stated:
        return stated
    folded = (target or "").strip().casefold()
    if not folded:
        return None
    if folded.endswith("$") or folded.rsplit("\\", 1)[-1] in BUILT_IN_PRINCIPALS:
        return "host"
    return None


def yn(v):
    return None if v is None else str(v).lower() in ("y", "yes", "true", "1")


def classify(action, confidence, severity, reversible=None, stops_critical=None, irreversible=None, mass=None, preset=None,
             target=None, target_kind=None):
    kind = identity_kind(target, target_kind)
    if preset in IDENTITY_ACTIONS and kind == "host":
        return {"action": action, "target": target, "target_kind": kind, "tier": "not selected",
                "matrix_entry": ["a host's own identity: an identity action contains no one, and every service of "
                                 "the host runs under it (Incident Response §1, §2.1)"],
                "instead": "contain the host: isolate it (isolate-workstation; isolate-server or "
                           "isolate-domain-controller where the host serves)",
                "record": "nothing: the action is not proposed, and no approval is requested for it"}
    if preset:
        p = PRESETS[preset]
        reversible = p[0] if reversible is None else reversible
        stops_critical = p[1] if stops_critical is None else stops_critical
        irreversible = p[2] if irreversible is None else irreversible
        mass = p[3] if mass is None else mass
    reasons = []
    if confidence == "Low": reasons.append("Low confidence: every containment action requires approval")
    if stops_critical: reasons.append("stops a critical service (Crown Jewel asset or a service identity a critical service runs under)")
    if irreversible or reversible is False: reasons.append("not reversible")
    if mass: reasons.append("affects many entities at once")
    tier = "requires approval" if reasons else "pre-authorized"
    if severity in ("High", "Critical"):
        timing = "apply immediately, before the internal notification completes; stakeholders confirm afterwards or request rollback"
    else:
        timing = "may be scheduled with the affected asset owner when applying it at once would disrupt work; record the schedule on the action entry"
    r = {"action": action, **({"target": target, "target_kind": kind} if target else {}), "tier": tier, "matrix_entry": reasons or ["reversible, leaves the entity's service running"], "timing": timing if tier == "pre-authorized" else "after approval; while pending, apply the pre-authorized actions and continue the investigation of residual observations",
         "record": "an `action` entry on the Case: the action, entity, timestamp and rollback"}
    if tier == "requires approval":
        r["presentation_payload"] = {
            "1_context": "Incident Category, Case severity and confidence, and in plain language why the Malicious hypothesis was proven (score and carrying observations)",
            "2_evidence": "the observations, each with its tag, event references and queries",
            "3_action_and_matrix_entry": f"{action}"
            + (f" on {target}" + (f" ({kind})" if kind else "") if target else "")
            + " — requires approval because: " + "; ".join(reasons),
            "4_blast_radius": "expected effect on operations",
            "5_rollback": "the exact call, script or procedure that reverses it, or the statement that it cannot be reversed",
            "decision_recorded_in": "the action entry (approved / modified / rejected); HITL dwell time measured, never counted as containment time",
        }
    return r


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--action", required=True)
    ap.add_argument("--confidence", required=True, choices=["Low", "Medium", "High"])
    ap.add_argument("--severity", required=True, choices=["Informational", "Low", "Medium", "High", "Critical"])
    ap.add_argument("--preset", choices=sorted(PRESETS))
    ap.add_argument("--reversible"); ap.add_argument("--stops-critical-service"); ap.add_argument("--irreversible"); ap.add_argument("--mass")
    ap.add_argument("--target", help="the entity the action acts on, as the Case names it")
    ap.add_argument("--target-kind", choices=["person", "service", "host"],
                    help="for an identity: a person's account, a service identity, or a host's own identity")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    r = classify(a.action, a.confidence, a.severity, yn(a.reversible), yn(a.stops_critical_service), yn(a.irreversible), yn(a.mass), a.preset,
                 a.target, a.target_kind)
    if a.json:
        print(json.dumps(r, indent=2))
        sys.exit(1 if r["tier"] == "not selected" else 0)
    print(f"{r['action']}: {r['tier'].upper()} — " + "; ".join(r["matrix_entry"]))
    if "instead" in r:
        print("Instead: " + r["instead"])
        sys.exit(1)
    print("Timing: " + r["timing"])
    print("Record: " + r["record"])
    if "presentation_payload" in r:
        print("Presentation payload to fill in (Guardrails §2):")
        for k, v in r["presentation_payload"].items():
            print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
