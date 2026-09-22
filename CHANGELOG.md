# Changelog

## Unreleased — conforms to zerosoc-framework@a5ef27c

- **What a source recommends is indicative, and nothing enforces it any more.** Four places held a
  run to answering every recommended action the source published: `note_elements.py` refused a Note
  carrying one without a disposition, `triage_decide.py` printed `DECISION NOT READY` and withheld
  `decision_ready`, `check_run.py` failed the run, and `alert_metadata.py` told the executor to go
  back and answer them. All four are gone, following the framework's §1.5. A source publishes its
  procedure on every alert it raises: measured on a live tenant, a 59-alert Case published 684
  recommended actions — 107 distinct instructions — and a **three-alert** Case produced a Triage
  Note of 67 findings, six of which decided it. What the executor **ran** is still held to naming
  the Finding it produced; what it did not run is neither a failure nor an entry, because a line
  recording that a recommendation was considered and found irrelevant is not evidence. The scripts
  still **report** what was run, declined and left alone — reporting is not requiring, and a reader
  of a decision can draw their own conclusion about what was left.

- **The alert-type map covers the alert titles four real incidents actually raised.** The map reads
  an alert, never the incident that holds it: measured over the alerts of whole incidents read from
  a lab tenant, 43 of 93 alerts across 13 distinct alert titles matched no rule and kept their own
  title as their type. The cost is what the type is for: one behaviour reported under two of the
  vendor's wordings counted twice instead of once (Detection & Analysis §1.1), and a ledger whose
  `alert_type` is a vendor string groups with nothing seen under another vendor's name. Choosing a
  playbook is not affected — that is done from the telemetry domain and the techniques the detection
  asserts, before this map is read. Ten of the
  thirteen now map — two of them to `Remote execution / lateral movement`, an Endpoint alert type
  the framework did not have until it was added for exactly this (ZeroSOC/zerosoc-framework#71):
  lateral movement had one home, and its telemetry was the network rather than the host. Where a
  detector id is stable it is matched first, as it should be; two detectors in these recordings
  carry more than one title, and because a detector id wins over any title match, binding them
  would have retyped alerts that were already right — those are matched by title, and a test holds
  them that way.
- **An alert a source cannot describe may now be left unmapped on purpose, with the reason.** A
  rule of `alert_types` either names the framework alert type its alerts carry, or declares
  `unmapped` and says why — the two forms are exclusive, and the schema refuses a rule that is
  both or neither. A source's correlation, attribution and containment records state a conclusion
  about a Case rather than a behaviour on an entity, and no alert type is true of them; three such
  titles are now recorded as decided rather than left looking like an oversight. The alert is
  flagged exactly as before and still deduplicates, so nothing about the run changes: what changes
  is that the maintainer's list of what to add no longer carries what was already settled.

## v0.4.1 (2026-09-21) — conforms to zerosoc-framework@b5f4966

Two defects found running the method surface of `v0.4.0` in a host that checks every Note at both
gates, which is what `note_elements.py` is for. Both are in the check and the packaging; the pin
and the method are unchanged, and nothing an implementation calls has moved.

- **A source the deployment cannot read is a visibility gap, not a Note nobody may write.**
  `note_elements.py` refused every Note of a deployment that declares no source profile: none of
  §1.1 can be read without the field names a profile carries, so each Alert rendered no assertion
  and the check called that non-conformant. The framework's answer to a source that cannot be read
  is the gap, which the run records — the check already honoured that for one assertion the source
  did not supply, and now honours it for a record it could not read at all. What a gap still does
  not excuse is an assertion the source supplied and the Note dropped.
- **The investigation skill carries the tables its own script reads.** `alert_metadata.py` ships
  in `zerosoc-investigation` and names a technique from the framework's tables; the alert catalog
  that holds those names was generated into `zerosoc-triage` alone, so at the investigation gate
  every technique came back unnamed — `T1486` included — and a Note that renders one is written
  bare, which §2.5 refuses. `02-Taxonomy/alert_types.md` is now generated into that skill too.

## v0.4.0 (2026-09-21) — conforms to zerosoc-framework@b5f4966

What one technology's records mean now has one versioned home, a deployment may override it locally,
and the method surface the framework owns — the rendering, the Case Timeline, the normative rule text —
ships here rather than in whatever runs the skills.

**Breaking, for an implementation moving from `v0.3.0`:**

- **`alert_type_map` and `--map` are gone.** The alert-type rules were absorbed whole into the source
  profile, together with `capabilities/alert_types.defender-xdr.json`. A binding that still declares
  `alert_type_map` is declaring a field nothing reads, and `tools/check_run.py` takes
  `--profile <source_profile.json>` where it took `--map`.
- **The binding names its profile as `zerosoc-defender-xdr/source_profile.json`.** Under
  `source_profiles`, keyed by the source identifier the binding already uses, and resolved against the
  tool skill installed beside the method skills — so a deployment installs the tool skill of each
  technology it runs on. What a deployment reads differently goes in a local override named under
  `source_profile_overrides`, not in fields of the binding.
- **Findings on the ledger gained `event_refs`, `first_seen` and `timeline`.** The decision rules read
  none of the three, so a `v0.3.0` ledger still decides the same way; the rest of the surface does read
  them. `timeline.py` derives T0 from the earliest Malicious `first_seen` and shows only what `timeline`
  flags, and `note_elements.py` fails a Finding that cites no event. A ledger written without them
  yields a Case with no timeline and a Note that does not pass its own check.

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
