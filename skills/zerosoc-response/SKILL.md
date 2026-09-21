---
name: zerosoc-response
description: Respond to a confirmed Incident under the ZeroSOC Framework (Phase 3). Confirms scope and category from the Investigation to Response contract, selects containment actions from the Incident Category playbook, classifies each under the autonomy matrix (pre-authorized or requires approval, with the presentation payload for approvals), then eradicates, recovers, handles NIS2 and DORA notification deadlines and hands over to post-incident activity. Use when a Case has verdict True Positive and an Investigation Note.
license: Apache-2.0
metadata:
  version: "0.4.0"
  framework: "zerosoc-framework@b5f4966 (2026-09-21)"
  status: draft
  author: ZeroSOC
---

# ZeroSOC Incident Response (Phase 3)

The Case arrives confirmed (`verdict_id = 2`) with its Investigation → Response contract. The assignee
carries it through containment, eradication and recovery; there is no separate incident commander. Every
action is its own entry in the Case's `finding_info_list`, typed `action`, carrying the Remediation
Activity event in `related_events` with its timestamp, entity and rollback. An action is recorded against
the Case and not against the Finding that prompted it: the reasoning may be retracted, and the action
still happened. Paths are relative to this
skill's directory.

Read once per session: [Incident Response](references/framework/03-Processes/03-response.md) (the method
and the autonomy matrix, §2.1) and [Guardrails §2–§3](references/framework/07-Governance/agentic_guardrails.md)
(approval payload, human assignee). Read per Incident: the playbook's Incident Response section.

## When to use

- A Confirmed Incident with its contract and Investigation Note. Not before: a Case without
  `verdict_id = 2` goes to the `zerosoc-investigation` skill.

## Inputs

- The contract: confirmed `incident_category`, scope (`observables`), `finding_info_list` (the Alerts,
  the Findings and any action already taken), `start_time` (the Incident's T0), `severity_id`,
  `confidence_id`, `impact_id`, `significant`, `cross_border`, `handover_reason`, `notes` carrying the
  Investigation Note, the recommended actions. A tool-initiated action that fired before any executor
  opened the Case is already an entry — this is where the **remediation the source performed per entity**
  is carried, blocked, quarantined or removed: read them before acting, so nothing is done twice and an
  entity the source left active is not mistaken for one it treated.
- The capability binding `zerosoc.capabilities.json` with the `containment.*` classes, `ticketing` and
  `notification`; the telemetry classes to verify containment and eradication.

## Procedure

1. **Confirm scope** (§1). From the contract confirm the affected entities and the category, read the
   confidence and severity Investigation resolved (they set what may run without approval), and check
   whether any entity is a Crown Jewel asset or a privileged identity: if so and the assignee is not
   human, the handover happens now and does not delay pre-authorized containment. Scope that expands
   during the response is recorded on the Case and the actions re-selected for the new entities.
2. **Regulatory clock** (§6, and Detection & Analysis §3.2). If the Incident is `significant`, the
   deadlines run from awareness: NIS2 early warning within 24 hours, notification within 72 hours, final
   report within one month; DORA initial, intermediate and final reports on the regulation's deadlines.
   Notification is the SOC Manager's responsibility; prepare the content from the Note and the timeline
   and record each notification (`notifications`: kind, recipient, deadline, sent time). Internal
   notification by severity: High within 30 minutes to asset owners and the security lead; Critical
   within 15 minutes to the CISO, legal, risk and executives (reference times).
3. **Select containment actions** from the playbook. Subtract what the source has already done: an
   entity it blocked, quarantined or removed needs no containment repeating on it, and the action is
   recorded as taken by the source rather than claimed by this run; an entity it left **active** keeps
   every action the matrix allows. Then run:
   `python3 scripts/select_playbook.py --category IC-01 --section "Incident Response" --bindings zerosoc.capabilities.json`
   prints the playbook version, its required data sources and the **Containment**, **Eradication** and
   **Recovery** lists. Actions marked **requires approval** are in the approval tier; every other action
   is pre-authorized subject to the Case confidence. When no playbook exists for the category at this
   framework pin, select actions from the matrix in §2.1 directly.
4. **Classify each action** under the autonomy matrix:
   `python3 scripts/autonomy.py --action "isolate WS-07" --preset isolate-workstation --confidence High --severity High`.
   Pre-authorized actions are reversible and leave the entity's service running (isolate a workstation,
   suspend sessions, disable an identity no critical service runs under, revoke a key or token, block an
   indicator, quarantine a file or message); they apply to any entity, a Crown Jewel included. Approval
   is required for actions that stop a critical service, are not reversible, affect many entities at
   once, or **whenever the Case confidence is Low**. At High or Critical severity pre-authorized actions
   run immediately, before internal notification completes; at Low or Medium severity they may be
   scheduled with the asset owner.
5. **Request approval** with the five-part payload the script prints
   ([Guardrails §2](references/framework/07-Governance/agentic_guardrails.md)): Context (category,
   severity, confidence, why Malicious was proven with score and findings), Evidence (findings with tags,
   event references, queries), the action and its matrix entry, Blast radius, Rollback. The same payload
   whoever the executor is; the SOC Manager is the default approver. Record the decision (approved,
   modified, rejected) on the action's entry; a rejection is a review event. While pending, apply the
   pre-authorized actions and continue investigating residual findings. Waiting time is HITL dwell, never
   containment time.
6. **Apply and record** each containment action: entity, timestamp, how it is reversed. Verify from
   telemetry that contained activity has stopped before eradicating (no lateral movement from isolated
   hosts, no traffic to blocked infrastructure, no successful authentication by disabled identities);
   correct containment that has not held.
7. **Eradicate** (§3): remove artifacts and the persistence the timeline identified (tasks, services,
   registry entries, web shells, mailbox rules, added credentials or consent grants); close the entry
   point (patch or configuration); rotate the credentials of identities the timeline confirms as
   compromised or exposed and of the secrets they could reach. A reset broader than the confirmed scope
   requires approval. A foothold not identified by the investigation expands the scope (step 1).
8. **Recover** (§4): monitor the affected entities for the verification window (24 hours of normal
   operation, reference value) before lifting containment; restore from known-good images or backups
   taken before T0 and check restored data for the eradicated artifacts; lift egress blocks, isolation
   and suspensions gradually, each removal recorded, with the Incident's detections kept active.
9. **Transition** (§5). When containment is lifted and services are restored, hand the Case, its
   timeline, Notes and metrics (T0, MTTD, MTTC, MTTR) to Phase 4 post-incident activity; feed indicators
   and lure patterns to Phase 1 as tuning signals.

## Governance

Just-in-time scope per action, Case-attributed calls, token metering. In **shadow mode** propose every
action with its matrix entry and apply none. An action in the approval tier applied without approval is a
critical failure of the run, as is any playbook-specific critical failure.

## Completion criteria

Containment verified, eradication complete, recovery verified and containment lifted; every action and
approval an `action` entry on the Case with its rollback; regulatory notifications recorded when the Incident is
significant; the transition to Phase 4 made.
