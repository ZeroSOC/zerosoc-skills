#!/usr/bin/env python3
"""Decide a response action under the autonomy matrix of Incident Response §2.1. Standard library only.

  autonomy.py --action "isolate workstation WS-07" --confidence High [--impact High] \
              [--preset isolate-workstation] [--action-impact None|Low|Medium|High|Critical] \
              [--target NAME] [--target-kind person|service|host|end-user-device] [--availability Low|Medium|High] \
              [--safety-function yes|no] [--reserved-class NAME] [--grant-up-to None|Low|Medium|High|Critical] \
              [--no-grant] [--stricter-cell Medium|High|approval] [--json]

The matrix reads three inputs, and none is the executor's own estimate: the Case **confidence**, as the
resolution rule produced it (--confidence); the Incident's **Impact**, as assessed at confirmation
(--impact); and the **impact of the action**, what the organization cannot use while the action holds.
When the Impact is not assessed (no --impact), the action requires approval.

The action's impact is one of five classes: None (nothing is lost, even if the Incident proves false),
Low (the service of one person or of one end-user device), Medium (a non-critical service, or the
service of a group of people), High (a critical service) and Critical (a network segment, many entities
in one action, or a service the whole organization depends on). --action-impact states it. Without it
the script derives it from the preset, the target's kind and the target's recorded availability
requirement (--availability; absent means none is recorded):

  a preset of a fixed class     the class the preset names, whatever the target (see PRESETS);
  any other containment action  High where the availability requirement is High: it stops an
                                availability-critical entity; else Low where the target is shown to be an
                                end-user device or a person's account; else Medium where an availability
                                requirement is recorded; else High: an entity the records do not show to
                                be an end-user device or a person's account, and whose availability
                                requirement is not recorded, is rated High.

A preset whose name states the target's kind (isolate-workstation, disable-user-identity,
disable-service-identity) shows it; --target-kind states it for the others and wins over the name.

The matrix is derived here from the likelihood and impact lookup the framework records (DD-35). The
executor applies an action without approval when the risk of waiting for a person is higher than the
risk of acting, and the action is proportionate: its impact is not above the Incident's Impact. The risk
of waiting combines the likelihood that the Incident is real (High, Moderate or Low at High, Medium or
Low confidence) with the Incident's Impact; the risk of acting combines the likelihood that it is false
(the complement) with the action's impact; equal risks require approval, and an action of no impact has
no risk of acting. Each cell is the lowest confidence at which the action is applied without approval. A
test compares every cell with the table of the skill's own copy of Incident Response §2.1.

An organization may add approvals and remove none. --grant-up-to is the highest action impact the
executor's autonomy grant covers, by action or at this time (Agentic Supervision §4); --no-grant says
automation or an agent holds no grant, and then every action requires approval. --reserved-class names a
class of entities the SOC Knowledge Base reserves and the target belongs to: every containment action on
it requires approval. --stricter-cell is the organization's own value for this cell, read only where it
asks for more than the matrix does. --safety-function yes says the action stops a safety function, which
is never stopped without approval.

The matrix covers containment only. An eradication or recovery action that destroys what the
organization holds (presets purge-email and wipe-reimage-delete), or a credential reset beyond the
confirmed scope (preset mass-credential-reset), requires approval and is given no cell (Incident
Response §3).

An identity action (suspending sessions, disabling an identity) targets a person's account or a service
identity (Incident Response §1). On a host's own identity (the computer account a directory gives a joined
device, an operating system's built-in principal such as SYSTEM) it is **not selected**: the host is
contained instead, by isolating it. `--target-kind` states what the target is; without it the name is read
for what it states (a trailing `$`, a built-in principal). A target not selected exits 1.

Output: `tier`, which is "applied without approval", "requires approval" or "not selected"; the three
inputs as read (`confidence`, `incident_impact`, `action_impact` with `action_impact_basis`); `cell`, the
matrix cell for the action's impact and the Incident's Impact ("Low or above", "Medium or above", "High",
"requires approval"; null where the Impact is not assessed or the action is outside the matrix);
`matrix_entry`, the sentences that decide it; `approval_reasons`, each with a `kind` (`matrix`: the
action's impact, the Incident's Impact and the confidence; `proportionality`; `grant-limit`;
`reserved-class`; `impact-not-assessed`; `safety-function`; `eradication-or-recovery`) and its `reason`;
and, when approval is required, the five-part presentation payload of Incident Response §2.1 to fill in,
whose third part states those reasons.
"""
import argparse, json, sys

ACTION_IMPACTS = ["None", "Low", "Medium", "High", "Critical"]
"""The five classes of an action's impact, on the Impact scale with None below it (Incident Response §2.1)."""
IMPACTS = ACTION_IMPACTS[1:]
"""The Incident's Impact (`impact_id` 1 to 4)."""
CONFIDENCES = ["Low", "Medium", "High"]

# DD-35: the likelihood that the Incident is real at each confidence, and that it is false, its complement
REAL = {"High": "High", "Medium": "Moderate", "Low": "Low"}
FALSE = {"High": "Low", "Medium": "Moderate", "Low": "High"}
# DD-35: the risk a likelihood and an impact give
RISK = {"High": {"Low": "Low", "Medium": "Moderate", "High": "High", "Critical": "Very High"},
        "Moderate": {"Low": "Low", "Medium": "Moderate", "High": "Moderate", "Critical": "High"},
        "Low": {"Low": "Low", "Medium": "Low", "High": "Low", "Critical": "Moderate"}}
RISKS = ["none", "Low", "Moderate", "High", "Very High"]


def proportionate(action_impact, incident_impact):
    """The action does no more harm than the Incident: its impact is not above the Incident's Impact."""
    return ACTION_IMPACTS.index(action_impact) <= ACTION_IMPACTS.index(incident_impact)


def waiting_outweighs_acting(confidence, incident_impact, action_impact):
    """The risk of waiting for a person is higher than the risk of acting; equal risks require approval."""
    waiting = RISK[REAL[confidence]][incident_impact]
    acting = "none" if action_impact == "None" else RISK[FALSE[confidence]][action_impact]
    return RISKS.index(waiting) > RISKS.index(acting)


def lowest_confidence(action_impact, incident_impact):
    """The lowest Case confidence at which the action is applied without approval, or None when it
    requires approval at every confidence."""
    if not proportionate(action_impact, incident_impact):
        return None
    return next((c for c in CONFIDENCES if waiting_outweighs_acting(c, incident_impact, action_impact)), None)


def cell_text(lowest):
    """A cell as the framework's table writes it."""
    if lowest is None:
        return "requires approval"
    return "High" if lowest == "High" else f"{lowest} or above"


def at_confidence(lowest):
    """The confidence a cell asks for, in a sentence."""
    return "at High confidence" if lowest == "High" else f"at {lowest} confidence or above"


def matrix():
    """The whole matrix: {action impact: {Incident Impact: cell}}."""
    return {a: {i: cell_text(lowest_confidence(a, i)) for i in IMPACTS} for a in ACTION_IMPACTS}


PRESETS = {
    # name: the class the preset fixes, or "by-target" for an action rated by what its target is
    "block-indicator": "None",             # an address or domain no entity of the organization uses
    "remove-threat-actor-artifact": "None",  # a rule, token, consent or account the records show the threat actor created
    "isolate-workstation": "by-target",    # an end-user device
    "isolate-server": "by-target",
    "egress-block": "by-target",           # a temporary egress block on a device
    "suspend-sessions": "by-target",
    "disable-user-identity": "by-target",  # a person's account
    "disable-service-identity": "by-target",
    "revoke-credential": "by-target",      # a specific key, token or certificate, rated by whose it is
    "blocklist-partner-network": "by-target",  # a connection to a third party, rated by what runs over it
    "quarantine-file": "Low",              # someone's own if the Incident is false
    "quarantine-email": "Low",
    "isolate-domain-controller": "Critical",  # stops the directory service
    "isolate-subnet": "Critical",          # a network segment
    "modify-routing": "Critical",
    "disable-many-identities": "Critical",  # many entities in one action
    "purge-email": "destroys",             # eradication or recovery: destroys what the organization holds
    "wipe-reimage-delete": "destroys",
    "mass-credential-reset": "beyond-scope",  # a reset beyond the confirmed scope
}

SHOWN_BY_PRESET = {"isolate-workstation": "end-user-device", "disable-user-identity": "person",
                   "disable-service-identity": "service"}
"""The presets whose name states what the target is."""

OUTSIDE_THE_MATRIX = {
    "destroys": "an eradication or recovery action that destroys what the organization holds requires approval "
                "(Incident Response §3); the matrix covers containment only",
    "beyond-scope": "a credential reset beyond the confirmed scope requires approval (Incident Response §3); the "
                    "matrix covers containment only",
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


def action_impact_of(preset=None, kind=None, availability=None, stated=None):
    """(the action's impact class, how it was read). `stated` wins; a preset of a fixed class is that
    class; any other containment action is rated by what its target is (Incident Response §2.1)."""
    if stated:
        return stated, "stated"
    fixed = PRESETS.get(preset) if preset else None
    if fixed in ACTION_IMPACTS:
        return fixed, f"the class of {preset}"
    shown = kind or SHOWN_BY_PRESET.get(preset)
    if availability == "High":
        return "High", "the target's availability requirement is High: the action stops an availability-critical entity"
    if shown in ("person", "end-user-device"):
        return "Low", ("a person's account" if shown == "person" else "an end-user device") + ": the service of one person or of one end-user device"
    if availability:
        return "Medium", f"the target's availability requirement is {availability}: a non-critical service"
    return "High", ("the records do not show the target to be an end-user device or a person's account, and its "
                    "availability requirement is not recorded: rated High")


def classify(action, confidence, *, impact=None, preset=None, action_impact=None, target=None, target_kind=None,
             availability=None, safety_function=None, reserved_class=None, grant_up_to=None, no_grant=False,
             stricter_cell=None):
    kind = identity_kind(target, target_kind)
    named = {"action": action, **({"target": target, "target_kind": kind} if target else {})}
    if preset in IDENTITY_ACTIONS and kind == "host":
        return {**named, "target": target, "target_kind": kind, "tier": "not selected",
                "matrix_entry": ["a host's own identity: an identity action contains no one, and every service of "
                                 "the host runs under it (Incident Response §1, §2.1)"],
                "instead": "contain the host: isolate it (isolate-workstation; isolate-server or "
                           "isolate-domain-controller where the host serves)",
                "record": "nothing: the action is not proposed, and no approval is requested for it"}
    reasons, entry, cell, rated, basis = [], [], None, None, None
    outside = OUTSIDE_THE_MATRIX.get(PRESETS.get(preset)) if preset else None
    if outside:
        reasons.append(("eradication-or-recovery", outside))
    else:
        # what a name states of the target ("host") decides only whether an identity action is selected
        rated, basis = action_impact_of(preset, target_kind, availability, action_impact)
        if impact is None:
            reasons.append(("impact-not-assessed", "the Incident's Impact is not assessed: the matrix has no cell to read, "
                                                   "and the action requires approval"))
        else:
            lowest = lowest_confidence(rated, impact)
            cell = cell_text(lowest)
            read = f"an action of {'no' if rated == 'None' else rated} impact at {impact} Impact"
            if lowest is not None:
                entry.append(f"{read} is applied without approval {at_confidence(lowest)}; the Case's confidence is {confidence}")
            if not proportionate(rated, impact):
                reasons.append(("proportionality", f"the action's impact ({rated}) is above the Incident's Impact ({impact}): "
                                                   "the action is not proportionate"))
            elif lowest is None:
                reasons.append(("matrix", f"{read} requires approval at every confidence: the risk of acting is never "
                                          "below the risk of waiting"))
            elif CONFIDENCES.index(confidence) < CONFIDENCES.index(lowest):
                reasons.append(("matrix", entry.pop()))
            if stricter_cell and not reasons:
                asked = None if stricter_cell == "approval" else stricter_cell
                if lowest is not None and asked is not None and CONFIDENCES.index(asked) <= CONFIDENCES.index(lowest):
                    entry.append(f"the organization's cell ({stricter_cell}) asks for no more than the matrix, and adds nothing")
                elif asked is None or CONFIDENCES.index(confidence) < CONFIDENCES.index(asked):
                    reasons.append(("matrix", f"the organization's stricter cell for {read} is "
                                              + ("requires approval" if asked is None else at_confidence(asked)[3:])
                                              + f"; the Case's confidence is {confidence}"))
        if safety_function:
            reasons.append(("safety-function", "the action stops a safety function, which is never stopped without approval"))
        if reserved_class:
            reasons.append(("reserved-class", f"the target is in a class of entities the organization reserves ({reserved_class}): "
                                              "every containment action on it requires approval"))
        if no_grant:
            reasons.append(("grant-limit", "the executor holds no autonomy grant: it requests approval for every action"))
        elif grant_up_to and ACTION_IMPACTS.index(rated) > ACTION_IMPACTS.index(grant_up_to):
            reasons.append(("grant-limit", f"the executor's grant covers actions up to {'no' if grant_up_to == 'None' else grant_up_to} "
                                           f"impact, and this action's impact is {rated}"))
    tier = "requires approval" if reasons else "applied without approval"
    r = {**named, "tier": tier, "confidence": confidence, "incident_impact": impact, "action_impact": rated,
         "action_impact_basis": basis, "cell": cell, "matrix_entry": [text for _, text in reasons] or entry,
         "approval_reasons": [{"kind": k, "reason": text} for k, text in reasons],
         "record": "an `action` entry on the Case: the action, entity, timestamp and rollback, and whether it was applied without approval or approved, and by whom"}
    if tier == "requires approval":
        r["presentation_payload"] = {
            "1_context": "Incident Category, Case severity and confidence, the Incident's Impact, and in plain language why the Malicious hypothesis was proven (score and carrying observations)",
            "2_evidence": "the observations, each with its tag, event references and queries",
            "3_action_and_matrix_entry": f"{action}"
            + (f" on {target}" + (f" ({kind})" if kind else "") if target else "")
            + " — requires approval because: " + "; ".join(text for _, text in reasons),
            "4_blast_radius": "expected effect on operations",
            "5_rollback": "the exact call, script or procedure that reverses it, or the statement that it cannot be reversed",
            "decision_recorded_in": "the action entry (approved / modified / rejected); HITL dwell time measured",
        }
    return r


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--action", required=True)
    ap.add_argument("--confidence", required=True, choices=CONFIDENCES, help="the Case confidence, as the resolution rule produced it")
    ap.add_argument("--impact", choices=IMPACTS, help="the Incident's Impact, as assessed at confirmation; absent when not assessed")
    ap.add_argument("--preset", choices=sorted(PRESETS))
    ap.add_argument("--action-impact", choices=ACTION_IMPACTS, help="the action's impact, where it is rated directly from the classes")
    ap.add_argument("--target", help="the entity the action acts on, as the Case names it")
    ap.add_argument("--target-kind", choices=["person", "service", "host", "end-user-device"],
                    help="what the records show the target to be: a person's account, a service identity, "
                         "a host's own identity, or an end-user device")
    ap.add_argument("--availability", choices=["Low", "Medium", "High"],
                    help="the target's recorded availability requirement; absent when none is recorded")
    ap.add_argument("--safety-function", help="yes when the action stops a safety function")
    ap.add_argument("--reserved-class", help="the reserved class of entities the target belongs to, as the SOC Knowledge Base names it")
    ap.add_argument("--grant-up-to", choices=ACTION_IMPACTS, help="the highest action impact the executor's autonomy grant covers")
    ap.add_argument("--no-grant", action="store_true", help="automation or an agent with no autonomy grant")
    ap.add_argument("--stricter-cell", choices=["Medium", "High", "approval"], help="the organization's own, stricter value for this cell")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    r = classify(a.action, a.confidence, impact=a.impact, preset=a.preset, action_impact=a.action_impact,
                 target=a.target, target_kind=a.target_kind, availability=a.availability,
                 safety_function=yn(a.safety_function), reserved_class=a.reserved_class, grant_up_to=a.grant_up_to,
                 no_grant=a.no_grant, stricter_cell=a.stricter_cell)
    if a.json:
        print(json.dumps(r, indent=2))
        sys.exit(1 if r["tier"] == "not selected" else 0)
    print(f"{r['action']}: {r['tier'].upper()} — " + "; ".join(r["matrix_entry"]))
    if "instead" in r:
        print("Instead: " + r["instead"])
        sys.exit(1)
    if r["action_impact"]:
        print(f"Action impact: {r['action_impact']} ({r['action_impact_basis']})  Incident Impact: {r['incident_impact'] or 'not assessed'}"
              f"  Confidence: {r['confidence']}  Cell: {r['cell'] or '-'}")
    print("Record: " + r["record"])
    if "presentation_payload" in r:
        print("Presentation payload to fill in (Incident Response §2.1):")
        for k, v in r["presentation_payload"].items():
            print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
