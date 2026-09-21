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

Three optional keys: `data_source_notes` (data source → why it is unavailable or limited; printed with the
gap), `source_profiles` (source identifier → the source profile of that technology) and
`source_profile_overrides` (source identifier → a [local override](#a-local-override) of that profile).

## Source profiles

A **source profile** is one versioned home for what one technology's records mean in the framework's
terms: where each required input of Detection & Analysis §1.1 lives, what the source's own words mean,
where every field of a record lands on the Case, and which capability classes it answers. It is declared
by [source_profile.schema.json](source_profile.schema.json), validated in CI by `tools/check_profiles.py`,
and it lives with the tool skill of its technology — the Defender XDR one is
`skills/zerosoc-defender-xdr/source_profile.json`. A binding names it from there,
`"defender-xdr": "zerosoc-defender-xdr/source_profile.json"`, wherever the binding itself is kept: the
profile is looked for beside the binding first, where a deployment's own copy wins, and then beside the
installed skills, so installing the tool skill next to the method skills is all a deployment does.

Its `alert_types` block is what makes "the same alert type on the same entity counts once"
deterministic: ordered rules from the source's detector id and alert title to a framework alert type and
its telemetry domain. `scripts/alert_types.py` applies it when the ledger is built and reports the alerts
no rule matches. Every `alert_type` in a profile must exist in the framework's `02-Taxonomy/alert_types.md`
(the tests check it). Detector ids are added as they are observed: they make a rule exact where a title is
ambiguous or localized.

Its `case_map` block is executable: a test walks sample documents of the source — every key one the source sends, every value invented — and fails on any key
that is neither mapped to a Case field nor ignored with a reason, so a field the vendor adds tomorrow is
not silence.

### A local override

The shipped profile is the default, and a deployment normally reads it as it is. When the source renames
a field or adds a word before the shipped profile follows, the deployment does not wait for a release: it
writes a **local override** beside its binding and names it under `source_profile_overrides`.

```json
{
  "overrides": "defender-xdr",
  "base_profile_version": "2026-09-21",
  "reason": "the source renamed remediationStatus on evidence items; the fix to the shipped profile is tracked in <ticket>",
  "profile": {
    "fields": { "evidence": { "remediation_status": "remediationState" } },
    "case_map": [
      { "path": "alerts[].evidence[].remediationState", "case": "finding_info_list[].types[]" }
    ]
  }
}
```

It is declared by [source_profile_override.schema.json](source_profile_override.schema.json) and holds
**only what differs**, so everything else keeps following the shipped profile across pin bumps: objects
are laid over the shipped ones key by key (`null` removes a key), an entry of `case_map` replaces the
shipped entry of the same `path`, the rules of `alert_types` are tried **before** the shipped ones, which
stay as they are, and any other list is replaced whole. It may not restate the `source` block, and a block
a profile does not have is refused rather than recorded and ignored. A title the shipped rules do not know
is therefore one small rule, and the shipped rule of the same alert type keeps following the releases:

```json
"profile": { "alert_types": { "rules": [
  { "alert_type": "Malware / loader execution", "domain": "Endpoint",
    "title_patterns": ["^a title only this tenant raises$"] } ] } }
```

The profile that results is held to the same schema and the same coherence as a shipped one. Check it
before using it, from a checkout of this repository at the release the deployment runs (the schemas and
the checker are not part of a packaged skill):

```bash
python3 tools/check_profiles.py --bindings /path/to/zerosoc.capabilities.json
```

The override is applied by the skills' own loader, so every script reads through it. A host that reads
the profile's JSON itself does not: give it the profile as the deployment reads it, which
`scripts/source_profile.py --bindings zerosoc.capabilities.json --effective` prints, and never the
shipped file.

An override is **on the record of every run read through it**. `scripts/source_profile.py --bindings
zerosoc.capabilities.json --json` prints the `source_profile` object for the ledger — the override's file
name, digest, reason and the paths it sets — and the source's `product` entry for the Case's
`provenance.products`, whose `feature.version` is the shipped profile's version followed by
`+local.<digest>`. `tools/check_run.py` recomputes the digest from the override file in the run and fails
a ledger that does not carry it, or a Note whose Provenance names neither that version nor the file.

An override is a stopgap. It names the version of the shipped profile it was written against; once the
shipped profile moves past that version the override is still read — a tenant does not break on a pin
bump — and every script flags it **stale**: check whether the fix it stood in for has landed, and delete
the override if it has.

## Where each assertion of a detection comes from

[Detection & Analysis §1.1](../framework/03-Processes/02-detection_and_analysis.md) makes six things the
detection asserts required inputs of triage: the technique identifiers, the threat name and family, the
detection source and detector, the remediation state of each entity, the source's description and its
recommended actions. Every source names them differently, and the scripts know no source, so the
source profile declares where each one lives and what the source's words for them mean:

- `fields.alert` — assertion → the field on the source's alert that carries it.
- `fields.evidence` — the remediation state and its details on an evidence item.
- `vocabularies.analytic_types` — the source's detection sources → the OCSF analytic each maps onto, as
  `{"type_id": 5, "type": "Fingerprinting"}` (Rule, Behavioral, Statistical, Learning (ML/DL),
  Fingerprinting). One the profile does not list is Other (99); the script never guesses.
- `vocabularies.remediation_states` — the source's states → whether the entity was **neutralized**, the
  OCSF Remediation Activity `status_id` and the activity it performed. A state the profile does not declare
  is recorded as reported and counts as **not** neutralized, because a state nobody declared is not
  evidence that anything was stopped.

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
