---
name: zerosoc-defender-xdr
description: What Microsoft Defender XDR's records mean in ZeroSOC Framework terms, and how to make it answer the framework's questions. Carries the machine-readable source profile every method skill reads - where each required triage input lives on an incident, what the source's own words mean, where every field of its records lands on the Case, and which capability classes it answers with what limits. Use it beside zerosoc-triage or zerosoc-investigation when the Case comes from this technology.
license: Apache-2.0
metadata:
  version: "0.1.0"
  framework: "zerosoc-framework@b5f4966 (2026-09-21)"
  status: draft
  author: ZeroSOC
---

# Microsoft Defender XDR, as the framework reads it

A **tool skill**: it holds what one technology's records mean and how to make it answer the
framework's questions. It states no method — the method is the framework's, and the method skills
execute it. Paths are relative to this skill's directory.

## 1. The source profile

[`source_profile.json`](source_profile.json) is the machine-readable half, validated against
`capabilities/source_profile.schema.json`. It is the **one** place this technology is described,
and every script that needs it reads it from there rather than from a copy:

| Block | What it settles |
|---|---|
| `source` | which technology this is, which API these paths are read from, and when the profile was last true of it |
| `fields` | where each required input of Detection & Analysis §1.1 lives on an incident, an alert and an evidence item |
| `vocabularies` | the source's own words in the framework's and OCSF's terms: severity, status, the OCSF analytic type each detection source is, and what each remediation state says it did |
| `alert_types` | detector id and title rules to the framework's alert types and telemetry domains |
| `case_map` | every path of a record: where it lands on the Case, or why nothing reads it |
| `extension` | the object this source keeps on the Case for what it states and the framework has no field for |
| `capability_coverage` | which capability classes and required data sources it answers, and where it stops |
| `queries` | per question kind, the recipe that asks it of this tool |

A deployment's capability binding names the profile under `source_profiles`, and the scripts of the
method skills take it from there:

```bash
# run from the method skill that needs them, which resolves the profile through the binding:
python3 alert_types.py alerts.json --bindings zerosoc.capabilities.json --json
python3 alert_metadata.py alerts.json --bindings zerosoc.capabilities.json --evidence evidence.json --json
```

## 2. What the profile settles, and what it does not

**It settles what the records mean.** A field renamed by the vendor is one edit here; nothing else
in the repository carries a second copy of it to drift from.

**It does not settle how to talk to the technology.** Authentication, endpoints, expansion, paging,
permissions and the query language belong to the integration, and change when the vendor's API
does rather than when the framework does.

**Every key is accounted for.** `case_map` names every path of a recorded incident — mapped to a
Case field, or ignored with the reason nothing reads it. A test walks recorded documents and fails
on a key that is neither, so a field the vendor adds tomorrow arrives with a noise rather than in
silence. That is the block to extend first when the source starts sending something new.

## 3. Reading this source's assertions

An incident of this source is a Case: same identifier, its alerts the Case's alerts, its evidence
the Case's observables. Three things about its own words are worth stating before any of them is
weighed:

- **A detection source is not a detection type.** `detectionSource` is which engine fired, and what
  kind of detection that is — rule, behavioural, model, fingerprint — is `vocabularies.analytic_types`.
  One the profile does not list is OCSF analytic type Other (99) and is never guessed at.
- **A remediation state says what the source did, not whether the Case is explained.** A state the
  profile does not list is recorded as reported and treated as **not** neutralized, because a state
  nobody declared is not evidence that anything was stopped. A remediation is an action of the
  Case, never a Finding that explains it (§1.5).
- **The source's own classification and determination are recorded and not weighed.** They sit on
  the extension object, visible to a reader, and the Case's verdict stays the executor's.
