# Changelog

## Unreleased

- **Acceptance harness for a live run.** `tools/check_run.py` recomputes what a run reported from the
  artifacts it produced: the evidence inventory against the evidence, the alert findings against the
  deployment map and the framework catalog, the timebox against the ledger's timestamps, the verdict
  against the rule, the sweep against the Note, and the binding against every data source the playbooks
  name. It also holds the run to the visibility-gap rule: every required source the binding marks
  unavailable must be a recorded gap, and a Case that records one cannot leave with High confidence
  (Playbook Architecture §7). It lists the source titles the map does not cover, to be reported back.
  Tested against faithful and unfaithful runs.

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
