# Changelog

## v0.2.0 (2026-09-17) — conforms to zerosoc-framework@bba8527

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
- **Measured timebox.** `resolve.py` computes the investigation timebox from `started_at` and the
  ledger's timestamps against the severity-scaled reference value (`--now`, `resolved_at`,
  `timebox_minutes`); a self-reported `timebox_expired` is a fallback and is labelled as such.
- **Retrospective sweep through the case store.** Investigation binds the 90-day sweep to `cases.store`,
  never to telemetry with a shorter retention.

## v0.1.0 (2026-09-15)

Triage, investigation and response skills with the coverage rule, the resolution rule and the containment
autonomy matrix as scripts.
