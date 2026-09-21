---
name: zerosoc-defender-xdr
description: What Microsoft Defender XDR's records mean in ZeroSOC Framework terms, and how to make it answer the framework's questions. Carries the machine-readable source profile every method skill reads - where each required triage input lives on an incident, what the source's own words mean, where every field of its records lands on the Case, and which capability classes it answers with what limits. Use it beside zerosoc-triage or zerosoc-investigation when the Case comes from this technology.
license: Apache-2.0
metadata:
  version: "0.3.0"
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
| `vocabularies` | the source's own words in the framework's and OCSF's terms: severity, status, its classification as the framework's verdict, the OCSF analytic type each detection source is, and what each remediation state says it did |
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

**A deployment does not wait for that edit.** The shipped profile is the default; when the source
changes before it does, the deployment lays a local override over it — a file beside the binding,
named under `source_profile_overrides`, holding only what differs — and every run read through it
records the override on its ledger and in the Case's provenance (`python3 source_profile.py
--bindings zerosoc.capabilities.json --json`). The override is a stopgap that is flagged stale once
the shipped profile moves on; the fix still belongs here.

**It does not settle how to talk to the technology.** Authentication, endpoints, expansion, paging,
permissions and the query language belong to the integration, and change when the vendor's API
does rather than when the framework does.

**Every key is accounted for.** `case_map` names every path of this source's incident record —
155 of them, measured against real incidents of a tenant, which are not published — each mapped to a
Case field, or ignored with the reason nothing reads it. A test walks sample documents that carry
every one of those paths, with invented values, and fails on a key that is neither, so a field the vendor adds tomorrow arrives with a noise rather than in
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

## 4. Which of the framework's questions this source answers

The machine-readable list is `capability_coverage` in the profile; this is what it is worth knowing
beside it. Nothing here restates the profile — where a class, a limit or a query recipe is
declared there, read it there.

| The method asks | This source answers with | What the answer is worth |
|---|---|---|
| **asset.cmdb** — what is this device? | the endpoint workload's own device record: platform, health, risk and exposure scores, the tags an operator set, the value they gave it | authoritative for anything the sensor onboarded, and silent for everything else. A device absent here is not a device that does not exist — it is a device this source cannot see, which is a visibility gap and not a clean result |
| **identity.directory** — who is this account? | what this source has seen of the account — the alerts it appears in and the devices it has used — and no directory record of its own | the account's role, privilege and standing come from the directory itself, never from here. An account outside the directory (a local account, a guest that never signed in) appears only where an alert named it |
| **malware.repository** — what is known about this file? | the vendor's own prevalence and verdict for a hash | one vendor's opinion. "No record" is an answer — a hash nobody has seen is evidence of rarity, which is not evidence of malice |
| **reputation.multi_engine** — what is this address or domain? | what this source has seen of it: the alerts it appears in and its prevalence in the tenant | one engine, not a consensus: the class is named for what the *method* wants, and this source answers the narrower question. Where a Finding turns on reputation alone, say whose |
| **cases.store** — has this been seen before? | the source's own incident history for the entity, bounded by its retention | it answers "has this source raised this before", not "has this happened before". A tenant onboarded three months ago has three months of history and no more |
| **telemetry.endpoint** — what ran, what was written, what connected? | the hunting tables | the strongest thing this source has, and the first thing a licence tier takes away. Always ask the binding, never the licence name |
| **telemetry.identity** — sign-ins and directory changes | the identity tables | empty where the identity workload is not deployed, and empty in a way that looks exactly like "nothing happened" unless the binding says the source is unavailable |

**The rule that follows from the last two rows:** on this source, an empty answer and an absent
capability are indistinguishable in the data. It is the deployment's binding — the capability
probe's output — that tells them apart, and the method treats an unavailable source as a
visibility gap with the check it prevented, never as a Benign finding.

## 5. Asking the telemetry well

The recipes are in the profile's `queries` block. What they do not say:

- **The window is 30 days** on the hunting tables, and it is the reason [Case Schema §3](references/framework/02-Taxonomy/case_schema.md) keeps the evidence a Finding rests on rather than a citation to it. A Case reported on at one month is reading events this source has already dropped.
- **Join on the device identifier, not the name.** A device is renamed, a name is reused, and two tenants' machines can share a hostname; the identifier is stable and is what the evidence rows carry.
- **A process is identified by three things together** — device, process id and creation time. A process id alone is reused within minutes on a busy host.
- **Every query is scoped to the Case's entities and its window before it is asked.** An answer that comes back with hundreds of rows is not evidence: it is a question that was not narrow enough, and the Case keeps the count and the query rather than an arbitrary slice of the answer.
- **Ask for the columns the Finding will reason from.** The command line is evidence and travels whole; the bulk of a row is not, and never reaches the Case.

## 6. What this source's own words are worth

- **`detectionSource` is which engine fired, not what kind of detection it is.** The profile's `analytic_types` is what turns one into the other, and a source it does not name is OCSF analytic type Other (99). The difference matters at triage: a signature match and a behavioural model are not the same evidence for the same claim.
- **An alert's severity stands in for a confidence this source does not state.** It says how bad, and nothing on an alert says how sure. The severity is kept as what it is — the severity of the Detection Finding the Alert Finding cites — and is *also* read as that Finding's confidence (Informational and Low give Low, Medium gives Medium, High and Critical give High). That second reading is a workaround and the profile says so: a High-severity alert from a noisy detector is not a High-confidence one, which is why triage validates it and never takes it at face value.
- **`classification` and `determination` are the source's verdict, and may be a human's or the product's.** An automated investigation writes them exactly as an analyst does, and the record does not always say which. They are recorded on the extension object and weighed by nobody: the Case's verdict is the executor's. The profile's `verdict` vocabulary says which framework verdict each classification *is*, so that the source's word can be read and the Case's verdict written back in the source's terms; two verdicts have no word here — Insufficient Data is not something this source can say, and a Duplicate is said by merging the incident, not by classifying it.
- **A remediation state says what was done to one entity, not that the Case is explained.** "The file was quarantined" leaves every question of §1.5 open — how it arrived, what ran before it was stopped, whether the same thing is on another device. The profile's `remediation_states` says which states neutralize something; a state it does not name is recorded as reported and treated as **not** neutralized, because a state nobody declared is not evidence that anything was stopped.
- **An automatic remediation is an action of the Case**, recorded with no side and no confidence, so that Response can see what is already contained without triage having treated it as an explanation.

## 7. The traps

- **Paging an incident re-reads it.** Reading an incident a page of alerts at a time suits a reader with a small budget per answer, and costs one complete expansion of the incident per page; on a live incident two pages can disagree with each other. A reader that wants the record takes it whole, in one call.
- **A merge moves an incident.** A merged incident carries `redirectIncidentId` and its evidence, its comments and its updates live on the master. Follow the chain first; write where the analyst will read.
- **The same entity is named two ways.** The source lists one process more than once when alerts describe it differently — no image file, another path, a different verdict. They are one process where the device, the process id and the creation time agree, and counting them twice inflates every count a Note reports.
- **A field that exists is not a field that is filled.** On a lower tier the column is there and empty. Treat an empty required input as the visibility gap it is: §1.1's inputs are read from the profile's field paths, and one the source did not supply is recorded with the check it prevented.
- **The evidence of an alert is not telemetry.** It is the entities the detection cited. A process the detection did not flag is not in the evidence, and looking for it there and finding nothing is not evidence of absence.

## 8. Where this knowledge comes from

Product knowledge is commoditised and much of it is published, including as skills under open
licences; distilling from those is allowed here under three conditions, and the third is the one
that matters: **only the commodity half**. What is published is how the product works. What has to
be written here is which of its answers settles which framework check, and what that answer is
worth — and no public source can know that.

The other two conditions are mechanical. Attribution is kept as the licence requires, in `NOTICE`,
naming the source, its licence and the **commit** distilled from; and a public skill is a
supply-chain input, so it is distilled from a reviewed commit and never fetched at build time.

Everything above is written from this project's own integration with the source, its capability
probe and its recorded incidents; nothing has been distilled from an external skill, and `NOTICE`
therefore names none. The day one is, it is pinned and credited there.
