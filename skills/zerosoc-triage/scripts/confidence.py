#!/usr/bin/env python3
"""The confidence an alert carries as a triage Observation, and the weights the rule reads it by.
Standard library only.

Detection & Analysis §1.5: an alert is weighed at the confidence its tool assigned, or, when the
tool gives none, at the level its severity maps to. The source's remediation never lowers that
confidence, so a detection the source attributes to a malware family — high-fidelity however low the
severity it gave a threat it prevented — floors at Medium when the tool gives none. It reads High
only where the severity is High or Critical, and the family never lifts it above what the severity
gives. Both the ledger's alerts (``alert_types.py``) and the decision rule (``triage_decide.py``)
read confidence through here, so an alert is weighed the same way wherever it is read.
"""

W = {"Low": 1, "Medium": 2, "High": 3}
LEVELS = ["Low", "Medium", "High"]
SEV2CONF = {"Informational": "Low", "Low": "Low", "Medium": "Medium", "High": "High", "Critical": "High"}


def alert_confidence(alert):
    """The confidence of an alert as an Observation: the tool's, else its severity, floored at Medium
    for a detection that names a malware family (``threat_family``) when the tool gives none."""
    stated = str(alert.get("confidence") or "").capitalize()
    if stated in W:
        return stated
    mapped = SEV2CONF.get(str(alert.get("severity") or "Medium").capitalize(), "Medium")
    if alert.get("threat_family") and W[mapped] < W["Medium"]:
        return "Medium"
    return mapped
