# Changelog

## Unreleased — conforms to zerosoc-framework@b5f4966

- **A source profile: one versioned home for what a technology's records mean.** What this project
  knew about Microsoft Defender XDR was spread over six files in three repositories, and two of them
  had already drifted — each declared what the source's remediation states mean, and one knew only
  the states that neutralize something, so a remediation the source *attempted and failed* was
  silently nothing. `capabilities/source_profile.schema.json` declares the profile and
  `tools/check_profiles.py` validates every one of them in CI. The first is
  `skills/zerosoc-defender-xdr/source_profile.json`, a **tool skill** beside the method skills: where
  each required input of §1.1 lives, what the source's words mean in the framework's and OCSF's
  terms, the alert-type rules, the capability classes it answers with their limits, the query recipes,
  the extension object it keeps on the Case — and `case_map`, every path of its records mapped to a
  Case field or ignored with a reason. That block is executable: a test walks sample documents of the source and
  fails on a key that is neither, so a field the vendor adds tomorrow is not silence. The binding names
  profiles under `source_profiles`; `alert_type_map` and `capabilities/alert_types.defender-xdr.json`
  are gone, absorbed whole.
- **A deployment may override the shipped profile locally.** After the source profile, a field the
  vendor renames is fixed by a pull request here, a pin bump and a release of whatever runs the
  skills — while the tenant stays broken, and the first hotfix outside the profile brings the
  duplication straight back. The binding now names a local override under `source_profile_overrides`
  (`capabilities/source_profile_override.schema.json`). It holds only what differs and is laid over the
  shipped profile, so the rest keeps following it across pin bumps; the profile that results is held to
  the same schema and coherence (`tools/check_profiles.py --bindings`). The shipped profile stays the
  default. A local alert-type rule is tried before the shipped ones, which stay as they are, so a title
  the shipped rules do not know is one small rule. A reader that takes the profile's JSON itself, and not through the loader, is given
  the profile as the deployment reads it (`scripts/source_profile.py --effective`). A run read through
  an override says so: `scripts/source_profile.py` prints the record for
  the ledger and the source's entry for the Case's `provenance.products`, whose profile version carries
  the override's digest, and `tools/check_run.py` fails a ledger that does not carry it and a Note whose
  Provenance does not name it. An override
  names the shipped version it was written against and is flagged stale — never refused — once the
  shipped profile moves past it.
- **The tool skill's other half: the expertise.** `skills/zerosoc-defender-xdr/SKILL.md` says which of
  the framework's questions this source answers and what each answer is worth — that an absent
  capability and an empty answer are indistinguishable in its data, so the binding is what tells them
  apart; that its own verdict may be a human's or the product's and is weighed by nobody; that a
  remediation state says what was done to one entity and never that the Case is explained; and the
  traps that cost real runs, from a merge that moves an incident to one process listed twice because
  two alerts described it differently. It cites the profile and restates none of it.
- **The method surface moves here: rendering, the timeline and the rule text.** A rule the framework
  changes should be a skills release and a pin bump; three of them needed a patch somewhere else as
  well, because something else owned them. All three scripts read **the ledger** the decision rules
  already run on, so nothing is copied into a second shape: a finding now also says the events it
  rests on (`event_refs`), when the thing it reports happened (`first_seen`) and whether the
  narrative shows it (`timeline`).
  `select_playbook.py` returns the playbook's **candidate Incident Categories** in the playbook's
  own order — for the alert type that fired, since a whole playbook has no "first" one and gives
  them per alert type — reading the element whole where it wraps or lists.
  `timeline.py` builds the **Case Timeline** and **derives T0**, the earliest Malicious
  `first_seen`: context may come before it, a Malicious entry may not. It flags the one entry that
  carries T0, reads ISO 8601 and epoch milliseconds alike, and fails a T0 no entry carries, a stated
  T0 the findings contradict, and a finding placed by when it was made instead of when it happened.
  `note_elements.py` prints the elements of a conformant Note **as the framework names them**, with
  all it says each contains, and checks an assembled one: a side without a confidence, context with
  one, a finding that cites no event, a technique code written bare anywhere in the Note — and
  `T1114.003 (Name)` is not one — an Alert that renders nothing of what its detection asserted, a
  recommendation followed that names no Finding, a gap that names no check. An element the framework
  renames or adds is required under its new name **with no change to the script**, and one it cannot
  read stops it. It renders the structure and runs the checks — the prose stays the executor's,
  because a Note written by a template would be a form and the framework asks for an account.
  And the **normative rule text** ships as skill content (`rules/*.md` in the triage and
  investigation skills), in the framework's words and naming nothing the skills do not define, so a
  human reading the skill and a model reading a prompt are held to one wording. `check_skills.py`
  holds the rule files to what it holds a `SKILL.md` to.

The framework pin moves 37 commits, from before the Case Schema was mapped natively to OCSF, and
now sits on `main` at the merge of framework PR #66. The three skills were instructing an agent to
produce Notes whose elements the framework no longer defines, and to hand on two fields the Case
Schema now rejects.

- **What a Note summarizes, the Case keeps.** The framework's evidence rule changed with the pin: a
  Finding's evidence is kept with the Case and cited by identifier, not cited alone, because a
  citation is evidence only while the source still holds the event. The Note still summarizes and
  still pastes no raw log; the instruction now says which of the two is which.

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
