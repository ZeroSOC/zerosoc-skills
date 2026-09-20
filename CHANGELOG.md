# Changelog

## Unreleased — conforms to zerosoc-framework@c6fb175 (PR #66)

The framework pin moves 35 commits, from before the Case Schema was mapped natively to OCSF. It is
ahead of `main` while framework PR #66 is open, and is re-pinned to the merge commit when it lands. The three
skills were instructing an agent to produce Notes whose elements the framework no longer defines, and to
hand on two fields the Case Schema now rejects.

- **What the detection asserts is read before enrichment.** The skills read the Alerts for their entities
  and their type and dropped everything the detection said about the threat. The new
  `scripts/alert_metadata.py` extracts the six required inputs of Detection & Analysis §1.1 — the
  technique identifiers, the threat name and family, the detection source and detector, the per-entity
  remediation state, the source's description and its recommended actions — under the field names the
  deployment's map declares under `detection_metadata`, and records them in the ledger. The techniques
  resolve against the framework's own tables into candidate Incident Categories, a sub-technique falling
  back to its parent (`select_playbook.py --technique`), and they now count in the confidence leaving
  triage, which rises on alerts of different **techniques** and not only of different types. Each
  recommended action is followed or set aside with a stated reason: `triage_decide.py` refuses to call
  the decision ready while one is unread, and `check_run.py` fails a run that leaves one. An entity the
  source already blocked, quarantined or removed is recorded and never weighed — it is an action of the
  Case, not an explanation of it — and the questions it leaves open are named. An assertion the source
  does not supply is a visibility gap with the check it prevented, so a deployment carrying none of them
  still runs and degrades on the record.

- **Both Notes render the Case, in one element structure.** Classification first, and it carries the
  decision: Close or Promote at triage, the verdict at investigation, beside severity, confidence, impact
  and the category. Then Summary, Findings, Rationale, Case Timeline, Visibility Gaps, Provenance. The
  Investigation Note gains a Summary. `zerosoc-triage` and `zerosoc-investigation` write to this
  structure and no longer point at the deliverable templates, which are being rebuilt.

- **Three elements dissolved.** *Actions Taken* — the check that produced a Finding is that Finding's
  `analytic`, rendered beside it. *Executed Queries* — a query that produced a Finding is the same
  `analytic`. *References* and *Evidence References* — the events are cited with each Finding, and the
  preserved-evidence pointer moved to Provenance.

- **`t0` and `timeline` are gone from the contracts.** T0 is the Case's `start_time`, which every Case
  carries: it opens at the earliest Alert and moves earlier whenever a Malicious Finding cites an earlier
  event. The Case Timeline is the Findings flagged `zerosoc:timeline`, rendered in `first_seen_time`
  order, not a field. `resolve.py` says so where it named the timeline as T0's source.

- **Response actions are entries on the Case.** `zerosoc-response` records each action as its own
  `finding_info_list` entry typed `action`, carrying the Remediation Activity event — against the Case,
  not against the Finding that prompted it, because the reasoning may be retracted and the action still
  happened. The skill now reads the entries on arrival, so a tool-initiated action that fired before any
  executor opened the Case is not done twice. `autonomy.py` follows.

- **Course of Action is the executor's.** The framework defines it that way, and the adversary's sequence
  is the course of the attack.

## v0.3.0 (2026-09-18) — conforms to zerosoc-framework@5f4ab24

The release the live acceptance run was made on, on two tenants (alert evidence only, and full process
telemetry).

- **A visibility gap no longer caps the Case's confidence.** The rule was removed from the framework, so
  `triage_decide.py` and `resolve.py` no longer lower the level when the ledger records a gap: confidence
  follows the findings that were gathered, and the gap is recorded in the Note and counted by the
  Visibility-Gap Rate. The playbook selector and both procedures say the same. `check_run.py` still holds a
  run to recording the gaps its binding implies.

- **Acceptance harness for a live run.** `tools/check_run.py` recomputes what a run reported from the
  artifacts it produced: the evidence inventory against the evidence, the alert findings against the
  deployment map and the framework catalog, the timebox against the ledger's timestamps, the verdict
  against the rule, the sweep against the Note, and the binding against every data source the playbooks
  name. It also holds the run to the visibility-gap rule: every required source the binding marks
  unavailable must be a recorded gap (Playbook Architecture §7). It lists the source titles the map does not cover, to be reported back.
  Tested against faithful and unfaithful runs.

- **Harness fixes from the acceptance runs.** `check_run.py` reads the triage alerts from either ledger
  shape, sees every playbook a run selected, and no longer counts a data source that a playbook names only
  to defer it; both ledgers record the selected playbook (`playbook`, `playbook_version`).

- **Process lineage from the evidence.** Triage and investigation rebuild the parent/child process chain
  of a Case with `scripts/process_chain.py`, from the rows of the evidence inventory: one node per
  process (device, PID, creation time) keeping every row's verdict, parents joined on PID and creation
  time with precision-aware times, lineage gaps for parents outside the evidence, anomalies reported, and
  timeline entries with their alerts as event references for the Case Timeline. The default view is one
  chain per alert, each process under its ancestors, as an alert story is read; ancestors contributed by the
  Case's other alerts are marked as context, and `--case` joins every alert into one chain per device.
  `--telemetry` fills the gaps where the deployment has process telemetry: the ancestors no alert cited are
  reconstructed up to the retention window and marked as coming from telemetry, so a Note can tell what the
  alerts asserted from what the chain reconstructed. Without it the chain stays evidence-only and the gaps are
  recorded as gaps. Nodes carry their command lines, decodings, remediation state, hashes, paths and accounts,
  cut to length in the text view and whole in the JSON. `--width` sets where a command is cut (0: whole).
  A decoding keeps its own lines, and the number of layers a command was encoded in is named in the chain
  when the source reports it.

## v0.2.0 (2026-09-17) — conforms to zerosoc-framework@b9c29f0

Fixes found running the three skills end to end against a live Incident.

- **Evidence inventory as a step.** Triage and investigation extract the Case's evidence before the
  ledger is started and record a completeness check (`scripts/evidence_inventory.py`: de-duplicated
  entities joined to their device, extracted count against the source's count). The decision scripts
  print a note when the inventory is missing, unverified or incomplete.
- **Reference binding for a licensing-limited deployment.**
  `capabilities/zerosoc.capabilities.defender-for-business.json` answers every data source the playbooks
  name, so playbook selection reports real visibility gaps with their reason instead of `unbound`. The
  binding schema gains the optional `data_source_notes` and `alert_type_map`.
- **Deterministic alert types.** `scripts/alert_types.py` maps source alerts to framework alert types
  from a deployment map (`capabilities/alert_types.defender-xdr.json`) and collapses the same type on the
  same entity; `resolve.py` counts alert findings of one type on one entity once.
- **Measured timebox.** `resolve.py` computes the investigation timebox from `started_at` to `--now`,
  `resolved_at` or the current time, against the severity-scaled reference value, which
  `timebox_minutes` may tighten and never extend; a self-reported `timebox_expired` is a labelled
  fallback; timestamps out of order are reported.
- **Re-pinned** to the framework's head (`b9c29f0`; no change in the mirrored documents since
  `bba8527`).
- **Retrospective sweep through the case store.** Investigation binds the 90-day sweep to `cases.store`,
  never to telemetry with a shorter retention.

## v0.1.0 (2026-09-15)

Triage, investigation and response skills with the coverage rule, the resolution rule and the containment
autonomy matrix as scripts.
