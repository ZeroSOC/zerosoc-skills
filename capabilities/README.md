# Capability classes and the binding file

The skills never name a vendor tool. They ask for **capability classes** — the enrichment and
telemetry capabilities the framework's method needs ([Detection & Analysis §1.2–§1.3](../framework/03-Processes/02-detection_and_analysis.md))
and the containment actions of the autonomy matrix ([Incident Response §2.1](../framework/03-Processes/03-response.md)).
An implementation, or an operator running the skills in an agent host, resolves each class to a concrete
tool in a **binding file**, `zerosoc.capabilities.json`, placed in the working directory or passed to the
scripts with `--bindings`. The schema is [zerosoc.capabilities.schema.json](zerosoc.capabilities.schema.json);
a starting point is [zerosoc.capabilities.example.json](zerosoc.capabilities.example.json).

The binding file has two maps:

- `capabilities`: capability class → `{ "tool": "...", "notes": "..." }`. The `tool` is whatever the host
  understands: an MCP server and tool name, a CLI, a query endpoint. The skill's Provenance section lists
  the classes it invoked, never the tool names.
- `data_sources`: the `required_data_sources` names used by the playbooks' frontmatter → `true` when the
  source is available to the executor, `false` otherwise. `scripts/select_playbook.py` compares a
  playbook's requirements with this map and emits the **visibility gaps** that the Notes must record and
  that cap the Case confidence at Medium.

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
