# Capability classes and the binding file

The skills never name a vendor tool. They ask for **capability classes** — the enrichment and
telemetry capabilities the framework's method needs ([Detection & Analysis §1.2–§1.3](../framework/03-Processes/02-detection_and_analysis.md))
and the containment actions of the autonomy matrix ([Incident Response §2.1](../framework/03-Processes/03-response.md)).
An implementation, or an operator running the skills in an agent host, resolves each class to a concrete
tool in a **binding file**, `zerosoc.capabilities.json`, placed in the working directory or passed to the
scripts with `--bindings`. The schema is [zerosoc.capabilities.schema.json](zerosoc.capabilities.schema.json);
a starting point is [zerosoc.capabilities.example.json](zerosoc.capabilities.example.json).

Two bindings ship as starting points: the generic example above, and
[zerosoc.capabilities.defender-for-business.json](zerosoc.capabilities.defender-for-business.json), the
reference shape of a licensing-limited deployment (alert evidence but no raw endpoint telemetry, no
query language). It answers `true` or `false` for every data source the playbooks name, so
`select_playbook.py` reports real visibility gaps, each with its reason, instead of `unbound`. A
capability probe run against the tenant supersedes it.

The binding file has two maps:

- `capabilities`: capability class → `{ "tool": "...", "notes": "..." }`. The `tool` is whatever the host
  understands: an MCP server and tool name, a CLI, a query endpoint. The skill's Provenance section lists
  the classes it invoked, never the tool names.
- `data_sources`: the `required_data_sources` names used by the playbooks' frontmatter → `true` when the
  source is available to the executor, `false` otherwise. `scripts/select_playbook.py` compares a
  playbook's requirements with this map and emits the **visibility gaps** that the Notes must record,
  each with the check it prevented. A gap does not change the Case's confidence.

Two optional keys: `data_source_notes` (data source → why it is unavailable or limited; printed with the
gap) and `alert_type_map` (the file name of the deployment's alert-type map).

## Alert-type maps

The framework counts the same alert type on the same entity once. An alert-type map makes that
deterministic for one alert source: ordered rules from the source's detector id and alert title to a
framework alert type and its telemetry domain. `scripts/alert_types.py` applies it when the ledger is
built and reports the alerts no rule matches. [alert_types.defender-xdr.json](alert_types.defender-xdr.json)
is the map for the XDR source of the profile above; every `alert_type` in a map must exist in the
framework's `02-Taxonomy/alert_types.md` (the tests check it). Detector ids are added as they are
observed: they make a rule exact where a title is ambiguous or localized.

## Where each assertion of a detection comes from

[Detection & Analysis §1.1](../framework/03-Processes/02-detection_and_analysis.md) makes six things the
detection asserts required inputs of triage: the technique identifiers, the threat name and family, the
detection source and detector, the remediation state of each entity, the source's description and its
recommended actions. Every source names them differently, and the scripts know no source, so the
deployment's alert-type map declares where each one lives under `detection_metadata`:

- `fields` — assertion → the field on the source's alert that carries it.
- `entity_fields` — the remediation state and its details on an evidence item.
- `analytic_types` — the source's detection sources → the OCSF `analytic.type_id` each maps onto (Rule,
  Behavioral, Statistical, Learning (ML/DL), Fingerprinting). One the map does not list is Other (99);
  the script never guesses.
- `remediation_states` — the source's states → whether the entity was **neutralized**, the OCSF
  Remediation Activity `status_id` and the activity it performed. A state the map does not declare is
  recorded as reported and counts as **not** neutralized, because a state nobody declared is not evidence
  that anything was stopped.

`scripts/alert_metadata.py` reads them, records the result in the ledger as `detection_metadata`, and
names every assertion the source did not supply as a **visibility gap** with the check it prevented — so
a deployment without them still runs, and degrades on the record instead of silently.

## Capability classes

| Class | Method reference | Used by |
|---|---|---|
| `reputation.multi_engine` | multi-engine reputation of hashes, IPs, domains, URLs (§1.2) | triage, investigation |
| `url.detonation` | URL rendering / detonation in an isolated sandbox (§1.2) | triage, investigation |
| `malware.repository` | malware-sample / behavioral repository lookup by indicator (§1.2) | triage, investigation |
| `domain.registration` | domain registration age / WHOIS (§1.2) | triage, investigation |
| `decode` | decoding / deobfuscation of command lines and payloads (§1.2) | triage, investigation |
| `asset.cmdb` | asset criticality, segment, OS and software (§1.2) | all |
| `identity.directory` | role, privilege, sessions, standard hours (§1.2) | all |
| `soc.knowledge_base` | exceptions, known-benign activity, maintenance windows, prior lessons (§1.2) | all |
| `cases.store` | active and prior Cases (§1.1, §1.3, §3.1 retrospective sweep) | all |
| `telemetry.endpoint` | EDR / endpoint process telemetry queries | all |
| `telemetry.identity` | identity provider sign-in and audit logs | all |
| `telemetry.network` | proxy, DNS, firewall, flow logs | all |
| `telemetry.email` | email gateway, mailbox audit, message trace | all |
| `telemetry.cloud` | cloud control-plane and workload logs | all |
| `siem.search` | cross-source search over normalized events | all |
| `containment.isolate_host` | isolate / reconnect an endpoint | response |
| `containment.suspend_sessions` | revoke the active sessions of an identity | response |
| `containment.disable_identity` | disable / re-enable an identity | response |
| `containment.revoke_credential` | revoke an API key, token or certificate | response |
| `containment.block_indicator` | block / unblock an IP, domain or URL at the perimeter or gateway | response |
| `containment.quarantine_file` | quarantine / release a file | response |
| `containment.quarantine_email` | quarantine / release a message cluster | response |
| `ticketing` | tuning tickets, incident tickets | all |
| `notification` | stakeholder notification channel | investigation, response |

Classes are added here when a playbook needs one that is missing; they are never renamed silently.
