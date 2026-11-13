---
name: zerosoc-response
description: Respond to a confirmed Incident under the ZeroSOC Framework (Phase 3). Confirms scope and category from the Investigation to Response contract, selects containment actions from the Incident Category playbook, decides each under the autonomy matrix from the Case's confidence, the Incident's Impact and the action's own impact (applied without approval or requires approval, with the presentation payload for approvals), then eradicates, recovers, handles NIS2 and DORA notification deadlines and passes the Case to post-incident activity. Use when a Case is a confirmed Incident (verdict True Positive at severity Low or above) with an Investigation Note.
license: Apache-2.0
metadata:
  version: "0.4.1"
  framework: "zerosoc-framework@555e891 (2026-11-13)"
  status: draft
  author: ZeroSOC
---

# ZeroSOC Incident Response (Phase 3)

The Case arrives confirmed (`verdict_id = 2` at `severity_id` 2 to 5) with its Investigation → Response contract. The assignee
carries it through containment, eradication and recovery; there is no separate incident commander. Every
action is its own entry in the Case's `finding_info_list`, typed `action`, carrying the Remediation
Activity event in `related_events` with its timestamp, entity and rollback. An action is recorded against
the Case and not against the Observation that prompted it: the reasoning may be retracted, and the action
still happened. Paths are relative to this
skill's directory.

Read once per session: [Incident Response](references/framework/03-Processes/03-response.md) (the method;
the autonomy matrix and the approval payload, §2.1), [Guardrails §2](references/framework/07-Governance/agentic_guardrails.md)
(the autonomy grant) and [Operational Metrics §2 and §4](references/framework/05-Metrics/operational_metrics.md)
(the gates G1 to G7 and the metrics measured between them). Read per Incident: the playbook's Incident
Response section.

The response passes four gates, and the Case's status follows them. The Incident stays In Progress
through **G4**, containment completed (the initial containment actions, planned at confirmation,
applied and confirmed), and **G5**, eradication verified. At **G6**, recovery complete, its
`status_id` is set to Resolved (4). It is Closed (5) at **G7**, when Phase 4 completes. A record of
the Case kept outside it, such as the source's incident or a ticket, never states a status the Case
does not carry.

## When to use

- A Confirmed Incident with its contract and Investigation Note. Not before: a Case without
  `verdict_id = 2` goes to the `zerosoc-investigation` skill.
- Not for a near miss (`verdict_id = 2` at `severity_id` 1): its activity did not reach the
  environment, and it is closed without response.

## Inputs

- The contract: confirmed `incident_category`, scope (`observables`), `finding_info_list` (the Alerts,
  the Observations and any action already taken), `start_time` (the Incident's T0), `severity_id`,
  `confidence_id`, `impact_id`, `significant`, `cross_border`, `attacks` (the
  Incident's techniques), `notes` carrying the Investigation Note, and the planned response actions:
  the `containment`, `eradication` and `recovery` tickets the investigation raised when it confirmed
  the Incident, in priority order. A tool-initiated action that fired before any executor
  opened the Case is already an entry — this is where the **remediation the source performed per entity**
  is carried, blocked, quarantined or removed: read them before acting, so nothing is done twice and an
  entity the source left active is not mistaken for one it treated.
- The capability binding `zerosoc.capabilities.json` with the `containment.*` classes, `ticketing` and
  `notification`; the telemetry classes to verify containment and eradication.
- What the SOC Knowledge Base records of each affected entity: its kind, its requirements on
  confidentiality, integrity and availability ([critical entity](references/framework/01-Foundation/definitions.md)),
  and the classes of entities the organization reserves for approval.
- For automation or an agent, its autonomy grant ([Supervision §4](references/framework/07-Governance/agentic_supervision.md)):
  whether it holds one for containment, and up to which action impact, by action or by time window.

## Procedure

1. **Confirm scope** (§1). From the contract confirm the affected entities and the category. Read the
   Case **confidence**, as the resolution rule produced it, and the Incident's **Impact**, as assessed
   at confirmation: with the impact of each action they decide what is applied without approval
   (step 4). You re-estimate neither. Read the kind and the
   requirements recorded for each affected entity: they rate the actions on it. Read what each affected
   **identity** is: a person's account, a service identity (an account or service principal software runs
   under), or a host's own identity (the computer account a directory gives a joined device, an operating
   system's built-in principal such as `SYSTEM`; OCSF's User of type System). An identity action is
   selected only for a person's account or a service identity the Case shows was used or exposed; a host's
   own identity is in the scope because something ran under it, and the host is contained instead. Scope
   that expands during the response is recorded on the Case, a technique it reveals joins the Case's
   `attacks`, and the actions are re-selected for the new entities.
2. **Regulatory clock** (§6, and Detection & Analysis §3.2). If the Incident is `significant`, the
   deadlines run from awareness: NIS2 early warning within 24 hours, notification within 72 hours, final
   report within one month; DORA initial, intermediate and final reports on the regulation's deadlines.
   Notification is the SOC Manager's responsibility; prepare the content from the Note and the timeline
   and record each notification (`notifications`: kind, recipient, deadline, sent time). Internal
   notification by severity: High within 30 minutes to asset owners and the security lead; Critical
   within 15 minutes to the CISO, legal, risk and executives (reference times).
3. **Select containment actions**, starting from the ones planned at confirmation (Detection & Analysis
   §2.5) and adding from the playbook as the scope expands. Subtract what the source has already done: an
   entity it blocked, quarantined or removed needs no containment repeating on it, and the action is
   recorded as taken by the source rather than claimed by this run; an entity it left **active** keeps
   every action the matrix allows. Then run:
   `python3 scripts/select_playbook.py --category IC-01 --section "Incident Response" --bindings zerosoc.capabilities.json`
   prints the playbook version, its required data sources and the **Containment**, **Eradication** and
   **Recovery** lists. A containment action carries no mark: the matrix decides it (step 4), and where
   its class is not plain the playbook says what decides its impact. The one mark, **requires
   approval**, is on an eradication or recovery action that destroys what the organization holds, or
   resets credentials beyond the confirmed scope. When no playbook exists for the category at this
   framework pin, select actions from §2.1 directly.
4. **Decide each containment action** under the autonomy matrix (§2.1):
   `python3 scripts/autonomy.py --action "isolate WS-07" --preset isolate-workstation --confidence High --impact High`.
   The matrix reads three inputs: the Case confidence, the Incident's Impact (`--impact`; when it is not
   assessed the action requires approval) and the **action's impact**, what the organization cannot use
   while the action holds, in five classes: None (nothing, even if the Incident proves false), Low (the
   service of one person or of one end-user device), Medium (a non-critical service, or the service of
   a group of people), High (a critical service), Critical (a network segment, many entities in one
   action, or a service the whole organization depends on). Rate it from the classes with
   `--action-impact`, or let the script derive it from the preset, `--target-kind`
   (`person`, `service`, `host`, `end-user-device`) and the target's recorded availability requirement
   (`--availability`): an entity the records do not show to be an end-user device or a person's
   account, and whose availability requirement is not recorded, is rated High. Rate an action by what
   the organization would lose, whoever owns the target, its side effects included; each action is rated
   on its own target, and reversing one is itself an action the matrix rates. An identity action on a
   host's own identity is **not selected** (the script exits 1 and names the host action to take
   instead): it is neither proposed nor sent for approval.
   The script prints the cell, the lowest confidence at which the action is applied without approval,
   and the result: **applied without approval**, or **requires approval** with the reason. The action
   is applied without approval only when the risk of waiting for a person is higher than the risk of
   acting and the action is proportionate, its impact no higher than the Incident's Impact. The matrix
   binds every executor: a person applies without approval what it allows; automation and agents do so
   within their autonomy grant (`--grant-up-to`), and with no grant (`--no-grant`) request approval for
   every action. An organization may add approvals and remove none: a stricter cell (`--stricter-cell`),
   a limit on the grant, and classes of entities it reserves in the SOC Knowledge Base
   (`--reserved-class`), on which every containment action requires approval. A safety function is
   never stopped without approval (`--safety-function yes`).
5. **Request approval** with the five-part payload the script prints
   ([Incident Response §2.1](references/framework/03-Processes/03-response.md)): Context (category,
   severity, confidence, the Incident's Impact, why Malicious was proven with score and observations),
   Evidence (observations with tags, event references, queries), the action and the reason the matrix
   gives for requiring approval (the action's impact, the Incident's Impact and the confidence; the
   proportionality condition; a limit of the grant; or the reserved class), Blast radius, Rollback. The
   same payload whoever the executor is. The approver follows the action's impact, e.g.: the owner
   of the service for High, the organization's crisis authority for Critical.
   Record the decision (approved, modified, rejected) on the action's entry; a rejection is a review
   event. While pending, apply what the matrix allows and continue the investigation. Waiting time is
   HITL dwell.
6. **Apply and record** each containment action: entity, timestamp, how it is reversed. An identity is
   contained **where it is held** (§2): an on-premises account is disabled in the directory that manages it
   and its synchronized cloud copy as well; sessions are ended by each system that granted them; a
   credential is reset where it is managed; a local account is disabled on the host that holds it. An
   action no means you hold reaches is handed to a person as a task stating the steps, keeps its place in
   the matrix (approved first where it requires approval), and is recorded under the name of whoever
   applied it. Verify from
   telemetry that contained activity has stopped before eradicating (no lateral movement from isolated
   hosts, no traffic to blocked infrastructure, no successful authentication by disabled identities);
   correct containment that has not held. Containment is completed (**G4**) when the initial
   containment actions are applied and confirmed: record when.
7. **Eradicate** (§3). The matrix covers containment only: an eradication or recovery action that
   destroys what the organization holds (a purge, a wipe, a re-image, a deletion) requires approval,
   requested as step 5 states, and `autonomy.py` answers so for the presets `purge-email` and
   `wipe-reimage-delete`. Remove artifacts and the persistence the timeline identified (tasks, services,
   registry entries, web shells, mailbox rules, added credentials or consent grants); close the entry
   point (patch or configuration); rotate the credentials of identities the timeline confirms as
   compromised or exposed and of the secrets they could reach. A reset broader than the confirmed scope
   requires approval (preset `mass-credential-reset`). A foothold not identified by the investigation expands the scope (step 1).
   Eradication is verified (**G5**) when every action is confirmed and no foothold is left: record when.
8. **Recover** (§4): monitor the affected entities for the verification window (24 hours of normal
   operation, reference value) before lifting containment; restore from known-good images or backups
   taken before T0 and check restored data for the eradicated artifacts; lift egress blocks, isolation
   and suspensions gradually, each removal recorded, with the Incident's detections kept active.
9. **Transition** (§5). When containment is lifted and services are restored, recovery is complete
   (**G6**): set the Case's `status_id` to Resolved (4) and hand the Case, its timeline, Notes and
   metrics to Phase 4 post-incident activity; feed indicators and lure patterns to Phase 1 as tuning
   signals. The metrics are those of Operational Metrics §4: T0, the Incident's `start_time`, anchors
   MTTD; MTTC runs from the originating Alert received (G1) to containment completed (G4); MTTR is
   Mean Time To Respond and starts at G1. Where MTTR stops is not yet settled in the
   framework, containment completed (G4) or eradication verified (G5): record the time of each gate
   and choose no stop of your own. Phase 4 closes the Case (**G7**, `status_id` Closed) when its
   review has been held and its action items recorded, or when no review is required.

## Governance

Just-in-time scope per action, Case-attributed calls, token metering. In **shadow mode** propose every
action with its matrix entry and apply none. An action applied without the approval it requires is a
critical failure of the run, as is any playbook-specific critical failure. A change of assignee is a
lifecycle event of the Case: any executor may take a Case over, and nothing in this procedure waits
for it.

## Completion criteria

Containment completed (G4), eradication verified (G5), recovery complete and containment lifted (G6)
with the Case Resolved; every action and approval an `action` entry on the Case with its rollback;
regulatory notifications recorded when the Incident is significant; the transition to Phase 4, which
closes the Case (G7), made.
