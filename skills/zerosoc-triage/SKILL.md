---
name: zerosoc-triage
description: Triage a security alert under the ZeroSOC Framework (Phase 2.a). Selects the domain triage playbook, enriches the entities, tags every finding Malicious or Benign with a confidence, applies the coverage rule to decide Close (False Positive, Benign, Duplicate) or Promote, and produces a conformant Triage Note plus the Triage to Investigation contract. Use when an alert, a detection, a user report or any suspected-incident intake needs a disposition.
license: Apache-2.0
metadata:
  version: "0.3.0"
  framework: "zerosoc-framework@b5f4966 (2026-09-21)"
  status: draft
  author: ZeroSOC
---

# ZeroSOC Triage (Phase 2.a)

Object: the **Alerts** of one Case. Outcome: exactly one of **Close** or **Promote**. There is no
"escalate". The method is the framework's; this skill sequences it, runs the deterministic parts as
scripts, and leaves judgment where the framework leaves it. Paths are relative to this skill's directory.

Read once per session, not per alert: [Detection & Analysis §1](references/framework/03-Processes/02-detection_and_analysis.md)
(the method) and the confidence table in [Definitions §7](references/framework/01-Foundation/definitions.md).
Read per alert: the playbook section the script prints.

## When to use

- A Security Alert (`Detection Finding [2004]`, `severity_id` at least Low) aggregated into a Case
  (`Incident Finding [2005]`). Signals (Informational) never trigger triage; consult them during it.
- An out-of-band report (user, IT ticket, CERT or vendor notice): register it first as an Alert and a Case
  (§5), then triage it here. Do not build a side process.
- Not for hunt-found activity: that enters Investigation directly (§4.3).

## Inputs

- The Case with its Alerts (id, type, entity, tool confidence or severity) and **what each Alert asserts
  about the threat**: its techniques, the threat name and family, the detection source and detector, the
  remediation state of its entities, the description and the recommended actions (§1.1).
- The capability binding `zerosoc.capabilities.json` (see the repository's `capabilities/` folder): it
  resolves capability classes to tools and states which `required_data_sources` are available.
- Access to the enrichment capability classes: `reputation.multi_engine`, `url.detonation`,
  `malware.repository`, `domain.registration`, `decode`, `asset.cmdb`, `identity.directory`,
  `soc.knowledge_base`, `cases.store`, and the telemetry classes for scope queries.

## Procedure

1. **Reception** (§1.1). Correlate to an open Case on the same host, identity or IP and append rather
   than open a new Case; consolidate repeats of one alert type from one source in the window into a
   summary signal (throttled alerts never enter triage). Set `status_id` to In Progress. Then **read the
   alerts**: detection logic, key fields, the relationships between aggregated alerts and entities. Form a
   first impression that directs the enrichment. Re-read the Case before every later step: tools append
   alerts and change severity while you work.
2. **Extract the evidence inventory.** Before any enrichment, list every entity the source attaches to
   the Case's alerts (devices, identities, processes with PID and creation time, files with hashes,
   addresses, URLs, registry keys, mailboxes), paging through every alert, as `evidence.json`. Run
   `python3 scripts/evidence_inventory.py evidence.json --source-count N`, where N is the number of
   evidence items the source itself shows for the Case. The script removes duplicates, joins each row to
   its device and prints the `evidence_inventory` object to record in the ledger. A mismatch is recorded and
   visible in every later script output: extract the rest, or state in the Note why it cannot be. When
   the source shows no count, record it as unverified. The Note's Summary states the figures ("31 of 31 entities extracted").
   When the inventory holds processes, run `python3 scripts/process_chain.py evidence.json --alerts alerts.json`
   for the parent/child lineage the [Artifact enrichment](references/framework/04-Playbooks/99-Shared/sub_enrichment_artifact.md)
   produces: one chain per alert, each process under its ancestors, as an alert story is read (`--case` joins
   the Case's alerts into one chain per device). Read the command lines, not only the names: they carry the
   objective, and the layers of encoding over them are part of the finding: a command hidden behind one
   layer is read for its intent, each further layer is a deliberate choice, and decoding stops at five.
   Two deployments, told apart by the binding, not by assumption:
   - **The endpoint class carries process telemetry.** Query the Case's devices and window for process
     creations (`device`, `pid`, `created`, `name`, `command_line`, `parent_pid`, `parent_created`) and pass
     them with `--telemetry telemetry.json`: the ancestors the alerts never cited are reconstructed and marked
     as coming from telemetry, and the chain is complete up to the retention window.
   - **It carries alert evidence only.** The chain holds what the alerts cited; a parent outside it is a
     **lineage gap**, never matched on the PID alone and never guessed. Gaps are normal here, not a failure:
     record them, and never argue from a lineage the evidence does not support. An alert whose evidence names
     no process has no chain, whatever the console draws from its own telemetry.
3. **Read what the detection asserts** (§1.1 names the six inputs, what each is for, and what to do
   with it; this step only sequences them). Before any enrichment, run
   `python3 scripts/alert_metadata.py alerts.json --bindings zerosoc.capabilities.json --evidence evidence.json --json`:
   it reads them under the field names the deployment's map declares and records what the source did not
   supply. Put the printed object in the ledger as `detection_metadata` — every later script reads it
   from there and the Note renders it — then:
   - Take the **techniques** to step 4: they are the first input to the candidate Incident Categories and
     to the playbook section (`scripts/select_playbook.py --technique T1003` resolves one alone, a
     sub-technique falling back to its parent). One the framework's tables do not hold widens nothing,
     and is recorded on the Case and named in the Note rather than dropped or renamed.
   - Take the **threat name and family** to step 6: they direct the enrichment and seed the hypotheses.
   - **Follow each recommended action, or set it aside with a stated reason**, and record the disposition
     on the action: `"disposition": "followed"` with the finding it produced, tagged like any other check
     on the evidence it returned, or `"disposition": "set aside"` with `"reason"`.
     `scripts/triage_decide.py` refuses to call the decision ready while one is unread.
   - Aim the checks of step 6 where the **remediation state** leaves them: at the entities the source left
     **active** first, and at what a block does not answer — how the entity arrived, what ran before it
     was stopped, whether the same thing is elsewhere. The state is recorded, never weighed (§1.5).
   An assertion the source does not supply is a **visibility gap**: the script names it with the check it
   prevented, and it goes in the ledger's `visibility_gaps` and in the Note. Never infer one from the
   alert title.

4. **Select the playbook and check visibility.** Identify the telemetry domain (Endpoint, Identity,
   Network, Cloud, Email, Data, Application, OT/ICS) and the alert type — the alert types the techniques of
   step 3 point at are the first candidates — then run:
   `python3 scripts/select_playbook.py --domain Endpoint --alert-type "Malware / loader execution" --bindings zerosoc.capabilities.json`.
   It prints the playbook version, the required data sources with their availability, the **visibility
   gaps** to record, and only the per-alert section you need. Record the selection in the ledger
   (`playbook`, `playbook_version`, `domain`): the Note's Provenance repeats it, and a Case whose
   playbook is not recorded cannot be reproduced. When no playbook exists for the domain at
   this framework pin, use the domain's alert catalog in
   [alert_types.md](references/framework/02-Taxonomy/alert_types.md) and apply §1.2–§1.5 directly.
   The rules you are held to while you run the checks are [rules/checks.md](rules/checks.md), given to any
   executor as they stand (`$language` in them is the language the deployment writes in).
5. **Start the ledger.** Create `ledger.json` (format in `scripts/triage_decide.py`) with the
   `evidence_inventory` object of step 2 and the `detection_metadata` of step 3. When the deployment names a source profile (the binding's
   `source_profiles`), build the alerts with `python3 scripts/alert_types.py alerts.json --bindings zerosoc.capabilities.json --json`:
   it gives each alert its framework alert type (detector id first, then title) and collapses the same
   type on the same entity to the strongest alert, so the rule below is applied the same way every time;
   an alert it reports as unmapped keeps its title as type. `python3 scripts/source_profile.py --bindings zerosoc.capabilities.json --json`
   prints the ledger's `source_profile` object and the source's entry for the Case's `provenance.products`:
   a **local override** of the shipped profile is recorded there and named in the Note's Provenance. Each independent
   alert is the first Malicious finding at the tool's confidence, or at the level its severity maps to
   (Informational/Low → Low, Medium → Medium, High/Critical → High). Same type on the same entity counts
   once.
6. **Enrich** (§1.2–§1.3), starting from what the detection already asserted rather than repeating it: a
   family it named is looked up for its behaviour, not re-attributed, and a question it has already
   answered is recorded with the detection as its source and asked again only where the decision turns on
   it and the answer can be checked independently. Go through the playbook's *Enrich entities* links (the `99-Shared` sub-playbooks;
   carry back their **Produces** outputs by name) and its numbered **Checks**. Query threat intelligence,
   the asset inventory, the directory, the SOC Knowledge Base, prior Cases, the 30-day history, lateral
   scope and the campaign check. **Egress rule**: only hashes and already-public IPs and domains leave the
   environment; never files, full URLs or message bodies; detonation only in an isolated sandbox.
7. **Tag every result** as the playbook prescribes: `Malicious` or `Benign` at Low, Medium or High
   (Definitions §7: High establishes the side alone, Medium is a strong signal needing a second, Low is
   consistent but common in normal operation). A result that bears on neither side is context, untagged.
   A `Benign (High)` finding is one that **explains** an alert: an approved exception or documented
   change in the Knowledge Base, an authorized test window covering the host and time, a known-benign
   recurrence with the same parameters. Check the playbook's **False Positive conditions** (the detection
   misfired) and **Benign conditions** (authorized activity that legitimately matches) and record which
   one applies, because they lead to different verdicts. A prior Case's verdict is context, never a
   verdict: verify its reasoning applies to *this* Case. A campaign firing across many entities becomes one
   campaign-level Case with severity for the campaign scope.
8. **Classify** (§1.4). Validate or override the source `severity_id` from asset criticality, identity
   privilege and blast radius, and state why. Record `impact_id` only when already known; never guess.
9. **Decide** by the coverage rule: `python3 scripts/triage_decide.py ledger.json`. It prints
   `DECISION NOT READY` while a recommended action of step 3 is neither followed nor set aside with a
   reason, and it repeats what the source already neutralized, so that no Case is closed because
   everything in it was blocked. The script closes
   only when no Malicious finding exists beyond the alerts *and* the Benign findings cover every alert
   (a High alert only by a `Benign (High)` finding; a Low or Medium alert by Benign weights summing above
   its own); otherwise it promotes, including when there is no finding at all. It also computes the
   confidence leaving triage. For a **Duplicate**, first validate all
   four criteria of §1.5 (matching core entities, overlapping timeline, active master Case, evidence
   merged), set `duplicate_of` in the ledger, and never treat the same alert on a different entity as a
   duplicate. Checklist before promoting or closing: can you say in one sentence, with evidence, why
   the activity is or is not suspicious? If not, gather more.
10. **Write the Triage Note.** The Note renders the Case and holds no state of its own: everything it shows is already
   on the Case, sampled at this gate. `python3 scripts/note_elements.py --kind triage` prints the elements in order
   and what each must contain, and `--note note.json` — the ledger with one field per element beside it — checks the
   Note against the framework's rules. The script renders the **structure** and runs the **checks**; the prose is
   yours ([rules/note-prose.md](rules/note-prose.md)). The canonical element list is [Detection & Analysis
   §1.6](references/framework/03-Processes/02-detection_and_analysis.md), and the order is part of it —
   **Classification** (severity, confidence, impact when known, the candidate categories, and the decision: Close or
   Promote, with `verdict_id` on a Close and the master Case id on a Duplicate); **Summary** (what happened and when,
   which entities were involved and who acted on whom, and the root cause where found — how it is known and how sure
   you are, in prose, which is not `confidence_id`); **Findings** (a table, alerts first, each with its tag, **what
   produced it** — the check is the Finding's `analytic` — and the events it rests on by OCSF identifier; each
   **Alert** also renders what its detection asserted: its techniques as `ID (Name)`, the threat name and family, the
   detection source and detector, and the remediation state of each entity it names, with the **disposition of the
   recommended actions** — each followed, with the Finding it produced, or set aside, with the reason); **Rationale**
   (the coverage rule applied in one or two sentences); **Case Timeline** (only the Findings flagged for it, which at
   triage is usually none — write "None."); **Visibility Gaps** (or "None."); **Provenance** (playbook path and
   version, executor classes, capability classes invoked, Case id). There is no Actions Taken element and no
   References element: the check that produced a Finding is rendered beside that Finding, and so are the events it
   cites.
   Name it `triage_note_<case-id>_<YYYYMMDD-HHMM>`.
   Technique codes are always `ID (Name)`: `scripts/alert_metadata.py` renders the ones the framework's
   tables name, and for the rest write the ATT&CK or ATLAS name — a bare identifier is not conformant.
   Summarize evidence in the Note and never paste raw logs — what the Note summarizes, the Case
   keeps: the events each Finding rests on stay on the Case and the Note cites them
   ([Case Schema §3](references/framework/02-Taxonomy/case_schema.md)).
11. **Emit.** On Close: `verdict_id` 1 (False Positive; also a tuning ticket to Phase 1), 5 (Benign; also a
    Knowledge Base entry if the exception was unrecorded) or 10 (Duplicate, with `master_case_uid`). On
    Promote: `verdict_id` stays 0 and the Case carries the **Triage → Investigation contract** of
    [Playbook Architecture §5](references/framework/04-Playbooks/playbook_architecture.md): `uid`,
    `status_id`, `severity_id`, `confidence_id`, `impact_id` when known, `start_time`, `observables`,
    `finding_info_list`, `attacks`, `candidate_incident_categories`, `entry_path`, `master_case_uid`
    when correlated, `visibility_gaps`, `provenance`, `desc`, and `notes` carrying the Triage Note.
    The contract states which fields must be populated at the boundary; one Case object crosses every
    phase, so nothing is copied. Then invoke the `zerosoc-investigation` skill.

## Governance

- Request permissions just in time for each query and let them expire when it completes; attribute every
  call to the Case id ([Guardrails §1](references/framework/07-Governance/agentic_guardrails.md)).
- A Crown Jewel asset or a privileged identity in scope makes a **human** the assignee from that moment
  (Guardrails §3, `handover_reason`); keep enriching and proposing, the human decides.
- Record token use per model invocation with the Case id; a budget exhaustion is not a failure: apply
  the coverage rule to the evidence at hand (Guardrails §5).
- Never close because similar Cases were closed before; never promote out of fear; never close to clear
  the queue.

## Completion criteria

Exactly one outcome recorded; the Triage Note conformant (every tagged Finding has an event reference,
what each detection asserted rendered with its Alert, every recommended action followed or set aside with
a reason, Visibility Gaps stated); on Promote the contract populated; on Close the verdict and its
emission done.
A Note whose Findings lack event references, or a close that leaves an alert uncovered, is
non-conformant and voids the run.
