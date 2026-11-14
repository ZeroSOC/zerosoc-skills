---
name: zerosoc-investigation
description: Investigate a promoted Case under the ZeroSOC Framework (Phase 2.b). Selects the Investigation and Response playbook by candidate Incident Category, verifies or retracts the triage observations, runs discriminating validation queries tagged Malicious or Benign with a confidence, resolves the verdict by score and coverage, tells an Incident from a near miss by whether the activity reached the environment, and produces the Investigation Note plus the Investigation to Response contract or the closure verdict. Use for a Case promoted at triage or opened by threat hunting.
license: Apache-2.0
metadata:
  version: "0.4.1"
  framework: "zerosoc-framework@555e891 (2026-11-13)"
  status: draft
  author: ZeroSOC
---

# ZeroSOC Investigation (Phase 2.b)

Object: the **hypothesis**. Two sides, always: the Malicious hypothesis (an attack, or an unauthorized
action against the organization's assets) and the Benign hypothesis (activity that is authorized,
expected or acceptable: administration, testing, scheduled work). Outcome: exactly one of a **Closed
Case**, a near miss included, or a **Confirmed Incident**: Malicious activity that reached the
environment. A Case that proves neither side is held On Hold, its questions asked, until an answer
decides it. Verdicts are computed from tagged observations, not argued. Paths are relative to this
skill's directory.

Read once per session: [Detection & Analysis §2–§3](references/framework/03-Processes/02-detection_and_analysis.md)
and the confidence table in [Definitions §7](references/framework/01-Foundation/definitions.md). Read
per Case: the playbook the script prints.

## When to use

- A Case promoted at triage, carrying the Triage → Investigation contract and its Triage Note.
- A Case opened by threat hunting (§4.3): it enters here directly and is by definition a detection
  false negative.
- Not for alerts without a Case or a Triage Note: run the `zerosoc-triage` skill first.

## Inputs

- The promoted Case and contract; the Triage Note with its tagged Observations, which **seed the score** and
  are verified, not re-collected, and with **what each Alert's detection asserted** (§1.1) — its
  techniques, threat name and family, detection source, per-entity remediation state, description and
  recommended actions, carried on the Case as `detection_metadata`. The Note also carries the conflict that promoted the Case: the
  Malicious observations beyond the alerts and the Benign observations they were weighed against.
- The capability binding `zerosoc.capabilities.json`; the telemetry classes (`telemetry.endpoint`,
  `telemetry.identity`, `telemetry.network`, `telemetry.email`, `telemetry.cloud`, `siem.search`), the
  enrichment classes and `cases.store`.
- The Case **token budget**, an organization setting. No clock closes a Case, and an exhausted
  budget leaves the resolution rule to be applied to the evidence at hand (Guardrails §4).

## Procedure

1. **Start the ledger from the Triage Note.** Read what triage did before anything else: the
   conflict that promoted the Case (the Malicious observations beyond the alerts and the Benign
   observations they were weighed against), the alert type it gave each alert, and the candidate Incident
   Categories it proposed. Create `ledger.json` (format in `scripts/resolve.py`) with every tagged
   Observation of the Note, its side, confidence, source artifact and event reference, the Case
   `severity`, and `at` on every observation as it is added. Alert observations carry
   their `alert_type` and `entity`, so the same type on the same entity counts once in the score. Carry
   the ledger's `source_profile` object across and refresh it with
   `python3 scripts/source_profile.py --bindings zerosoc.capabilities.json --json`: a local override of the
   shipped profile in force now is recorded on the ledger and in the Case's `provenance.products`, and
   named in the Note's Provenance.
2. **Extract the evidence inventory** for the Case as it is now: alerts are appended after triage, so the
   triage inventory is a starting point, not the answer. List every entity the source attaches to the
   Case's alerts as `evidence.json` and run
   `python3 scripts/evidence_inventory.py evidence.json --source-count N` (N: the distinct evidence items
   the source shows for the Case, not its rows per alert; `--source-basis reproduction` when a tool rebuilt
   N from the same evidence, which leaves a match unverified). Record the printed `evidence_inventory` object
   in the ledger; extract what is missing before scoring. For a hunt-opened Case the inventory is what
   the hunt collected, and N is unverified.
   When it holds processes, rebuild the lineage with `python3 scripts/process_chain.py evidence.json --alerts alerts.json`
   (one tree per device, every process once under its ancestors, each naming its alerts by the legend's labels
   and pointing to its decoded command, printed in full once under `scripts:`). Where the bound endpoint class carries process telemetry, query the Case's devices and
   window for process creations and pass them with `--telemetry telemetry.json --bindings zerosoc.capabilities.json` (the source profile says what the source calls its columns): the ancestors the alerts never
   cited are reconstructed and marked as such. Where it carries alert evidence only, the chain stops at the
   first ancestor no alert cited: that is a **lineage gap**, it is recorded, and no hypothesis may rest on a
   lineage the evidence does not show. Command lines, their decodings and the remediation state of each process
   are observations in their own right, not decoration, and so is the number of layers a command was encoded
   in: decoding stops at five rounds, and a command still encoded there is recorded as such.
   Keep the chain with the Case: the same command with `--ocsf --bindings zerosoc.capabilities.json` prints
   the `desc` and `related_events` of an Observation with no side, and the OCSF `events` they cite: a Process
   Activity per process (its `parent_process`, its `ancestry`, and the process that launched it as `actor`), a
   Script Activity per decoded command, and a Detection Finding per alert naming its processes in `evidences`.
   Record the Observation once and keep its events with the Case, and replace both when alerts that joined
   rebuild the chain; `--from-graph observation.json` prints its text again.
   Carry the Case's `detection_metadata` across and **refresh it at this gate**: alerts appended since
   triage bring their own assertions, and the remediation state changes while a Case is open. Re-run
   `python3 scripts/alert_metadata.py alerts.json --bindings zerosoc.capabilities.json --evidence evidence.json --json`
   on the Case as it now is, keeping the dispositions already recorded on the recommended actions. Give
   each alert triage did not type (appended since, or all of them on a Case that entered here) its
   type as triage does (its step 4) and add them with
   `python3 scripts/alert_types.py alerts.json --json`, whose entries are ready-made Malicious observations.
3. **Choose the Incident Category and select the playbook.** Triage's candidates are where you start, and
   the category is decided by the adversary's **objective and impact** (§2.2), read in
   [incident_categories.md](references/framework/02-Taxonomy/incident_categories.md) against what the
   Note and the inventory show, held to [rules/category.md](rules/category.md). Then run
   `python3 scripts/select_playbook.py --category IC-01 --section Investigation --bindings zerosoc.capabilities.json`.
   It prints the version, the required data sources, the visibility gaps to record, and the Investigation
   section (hypotheses, validation queries with their outcome tags, re-classification pivots). Record the
   selection in the ledger (`playbook`, `playbook_version`, `incident_category`), and again after a
   re-classification pivot: the Note's Provenance repeats it. If no
   playbook exists for the category at this framework pin, apply §2 directly with the category definition.
   Refine the two
   hypotheses to the Case (§2.1), starting the Malicious one from the **threat or family the detection
   named**: a named family has documented behaviour, persistence and follow-on activity, so the queries
   ask whether *those* are present rather than whether the activity is malicious in general. The name is a
   lead, not a verdict — an attribution the evidence does not support is retracted like any observation.
   Competing explanations within a side are sub-hypotheses that score for their side.
4. **Verify or retract** each triage observation, starting from the conflict (§2.2.1). An observation that does
   not hold or does not apply to this Case is marked `retracted` with the reason; the score is
   recomputed. Aim the first discriminating queries at the observations that conflict.
5. **Run the validation queries** (§2.2.3). The playbook's queries are indicative: choose the applicable
   ones, add what the Case calls for, and seek evidence *against* the favoured side. Each query is a
   question; translate it into the query language of the bound tool through the capability binding.
   Queries must be discriminating and state the reading of both outcomes, so a negative result is
   evidence too (a clean hash is a `Benign` observation, not silence). Tag each result as the query's mapping
   prescribes (`Malicious (…)` if …, `Benign (…)` if …), or as context; decide by judgment only when a
   result fits neither stated outcome. A Malicious observation records in `attacks` the techniques it
   shows. Observations from the same telemetry artifact count once. Record
   every query run, listed or added, with its outcome and tag, and list each result that carried no
   information under the ledger's `no_information_refs` and each query that covered the question and found
   nothing under `scoped_negative_refs`, as in triage: `resolve.py` gives the first no weight on either side.
   Egress rule as in triage: indicators only; several providers of one class as in triage, one
   observation per source.
6. **What the source already did is not coverage.** An entity the source blocked, quarantined or removed
   carries no side and no confidence at this gate either: it is an action the Case records, and the
   questions it leaves open — how the entity arrived, what ran before it was stopped, whether the same
   thing is elsewhere — are exactly what the validation queries answer. The source's recommended actions are
   indicative (§1.5): run the ones that bear on the Case, record each you run as the Observation it produced,
   and leave the rest alone.
7. **Mark coverage.** When the Benign explanation accounts for a Medium or High Malicious observation, set
   `covered: true` on it; uncovered Low Malicious observations never block a Benign verdict, they lower its
   confidence and are listed as residual observations.
8. **Resolve**, after reading the Case again (§1.1.6, §2.2.4): an alert that joined it since you read it is
   investigated here and never sent back to triage. Type it and add it as in step 2, extend the queries to
   what it adds, and judge whether it changes the verdict: a repeat of an alert type or technique the Case
   already holds adds little, a new technique shows the attacker progressing along the attack path, and a
   new targeted entity may be lateral movement. Then give the ledger its `alerts` (each alert's id and own confidence) and run
   `python3 scripts/resolve.py ledger.json`. Malicious is proven at a score of 3 or more when an alert is at High
   confidence or an observation stands beyond the alerts (one that only restates an alert counts as it);
   Benign at 3 or more *and* every Medium or High Malicious observation retracted or covered; the verdict and
   confidence follow the §2.4 table (confidence is the strongest carrying observation, never an average; on
   a proven Malicious side step 11 applies this rule again at confirmation). If neither side is proven, run the remaining discriminating
   queries, listed or added. **No clock closes a Case.** When no query is left that you can run
   (`no_query_left`), or the budget allows none (`budget_exhausted`), name in the ledger's `questions`
   the questions whose answers could prove a side, each with who can answer it (`asked_of`,
   `asked_at`), and run the script again: the outcome is **On Hold**, verdict Unknown (0), and the
   Case's `status_id` is On Hold (3) while the questions are asked. Each answer is an Observation,
   tagged with a side and a confidence like any check and named on its question (`answer`:
   `observation`); the Case returns to In Progress and is resolved again. The wait is HITL dwell
   time. The Case closes as **Insufficient Data** (7) only when no evidence that could prove either
   side can be obtained: every open question has been answered that the evidence `does not exist` or
   `cannot be reached`, with the reason, an answer that adds no Observation. It closes with a
   monitoring watch (`watch_until`: re-open on recurrence of the entities; active monitoring for the retention window at High or Critical
   severity) and a visibility or tuning ticket. Never "escalate".
9. **Re-classify on evidence drift** (§2.2.5). If the objective differs from or exceeds the candidate
   category, change `incident_category`, re-run step 3 for the new playbook, carry every observation
   forward, and record the pivot and its reason in the Note. The classification stays provisional until
   the Incident is confirmed (step 11).
10. **Before a close, read the scope of your grant** ([Supervision §4](references/framework/07-Governance/agentic_supervision.md)).
   Automation and agents close Cases only under an autonomy grant. The grant SHOULD cover a Case whose
   scope includes a [critical entity](references/framework/01-Foundation/definitions.md) (an asset or an
   identity with a High requirement on confidentiality, integrity or availability in the SOC Knowledge
   Base; a privileged identity is one by definition) only when its closing verdict, a near miss
   included, is at High confidence. Outside the grant, which is where a closing verdict below High
   confidence or one that carries no confidence (a Duplicate, Insufficient Data) falls, you propose the
   closure: a person decides on the Case's Note, and the Case is On Hold until then. An organization
   may narrow the grant further, by entity class as by alert type. Any executor may take a Case over:
   the change of assignee is a lifecycle event of the Case, and the same resolution rule applies
   whoever the assignee is (§2.3).
11. **On Malicious proven, assess reach first** (§2.5), held to [rules/reach.md](rules/reach.md): did the
    activity reach the environment? It did when something landed on a device, ran, persisted, was
    delivered to a person, or was gained; activity held in a gateway's quarantine, a sandbox or a decoy
    did not. Answer for the whole activity: a control's action on one alert does not make a Case a near
    miss. Record in the ledger's `reach` what each observation shows (`observations`: its `id`, `shows`
    and `what`; and `desc`, the answer in words) and run `python3 scripts/resolve.py ledger.json` again:
    the script computes the answer. Where no observation shows any of these, and one beyond the alerts
    shows a query that covered the rest of the activity and found nothing or where the activity was
    held, the outcome is a **near miss**: `verdict_id` 2 at `severity_id` 1, the Investigation Note
    written (step 13) and the Case closed without response; the rest of this step is skipped. In every other
    case the activity reached the environment and you **confirm the Incident**, before writing the
    Note. **Re-assess** the severity, which stays Low to Critical on an Incident, and the Incident
    Category from your understanding of the Incident (§1.4). The **confidence** is the resolution rule
    applied again to the Observations that stand: it is what `resolve.py` prints on the ledger as it now
    is, and you never set it by judgment. Record a value
    that changes, with its reason, in the Note's Rationale, and treat a change of category as a
    re-classification (step 9). **Estimate** `impact_id` from what is known: with the confidence it is
    an input of the containment autonomy matrix (Incident Response §2.1), so it is assessed here and
    never left for Response to guess. The confidentiality and integrity requirements the SOC Knowledge
    Base records for the affected entities bear on its informational effect and the availability
    requirements on its functional effect; an entity nobody rated counts as Medium. **Plan the initial response
    actions** from three inputs: the actions the source recommends, carried by the alerts; the actions the
    category's playbook describes; and your own judgment of the Case. Prioritize them, drop the unnecessary
    or redundant ones (disabling a local, non-domain account on a host already isolated is redundant), and
    add the ones the Incident, its context, its severity and the impact estimate call for; each planned
    action is a ticket the Case raises, of its kind (`containment`, `eradication`, `recovery`). Then set
    `verdict_id = 2`, with `severity_id` 2 to 5; record the definitive Incident Category and, in the ledger's `attacks`, the
    Incident's techniques, assessed from the Observations that stand: the Alerts' mappings are
    provisional, so one no Observation shows is left out and a broad one is narrowed (`resolve.py`
    lists the techniques the standing Malicious observations show and names any recorded that none
    shows); each goes on the Case's `attacks` under the tactic its use served in this Incident, judged
    from the attack path and the context the investigation established, and under more than one only
    where the Incident shows it served each; extend the **Case Timeline** triage compiled with the course of the
    attack (interleaved with the detection and the response actions that ran, each entry timestamped in UTC
    with its event reference; a process is an entry only through an Observation that establishes it, its
    `first_seen` the creation time the `timeline` of `process_chain.py --json` gives). The timeline says what happened and is not a field the Case stores: it is the
    Observations flagged `zerosoc:timeline`, rendered in `first_seen_time` order, with a `detection` entry per
    Alert and an `action` entry per response action that ran. Your validation queries are not entries: each is
    the Observation it produced, and a change of assignee is a lifecycle event. Give each observation its `first_seen` (when the thing happened, never when the
    observation was made) and `"timeline": true` where it establishes something that happened; `python3 scripts/timeline.py ledger.json --json`
    orders them, **derives T0** — the earliest Malicious `first_seen`; context may come before it — flags the one
    entry that carries it, and fails a T0 no entry carries or a Malicious entry earlier than the T0 the Case states. The Case's `start_time` opens at the earliest Alert and moves earlier
    whenever a Malicious Observation cites an earlier event; on a confirmed Incident it is **T0**, the
    earliest confirmed malicious event. Then, per §3.1, confirm the impact you estimated, and whether the
    Incident is **significant** under NIS2 Article 23(3) and **cross-border**; run the **retrospective
    entity sweep** through the `cases.store` capability class (Cases closed as False Positive or Benign
    in the last 90 days sharing the Incident's entities; never through `telemetry.*`, whose retention is
    shorter than the window; an unbound `cases.store` is a visibility gap; every match is flagged for QA
    review, never dismissed); pass the scope and the planned actions to response. At Low
    confidence the Incident is still declared; what is applied without approval is the matrix's to
    say, from the confidence, the Impact and each action's own impact.
12. **On Benign proven**: `verdict_id` 1 (False Positive, plus a `tuning` ticket to Phase 1) or 5 (Benign,
    plus an `exception` ticket — the Knowledge Base entry you propose and a person confirms — unless the
    Knowledge Base already holds it). Benign activity is authorized, expected or acceptable; it is
    acceptable when whoever is accountable for the asset, data or policy says so, and the observation
    cites that statement. Every close of this skill (False Positive, Benign, Duplicate, Insufficient
    Data, near miss) sets `severity_id` to 1 (Informational), as `resolve.py` prints: the source's own
    severity stays in `vendor_attributes`. Every close also sets `status_id` to Closed (5), at gate G3. Which of the two is the rule's, and
    `resolve.py` prints it: a Benign observation carries in the ledger the kind of the triage playbook
    condition it named, read off the list the condition is in — `"condition": "false_positive"` or
    `"benign"` — and the Case closes as Benign when the Benign observation of the highest confidence
    names a Benign condition, as False Positive otherwise, no condition named included. A Low-confidence
    close carries a monitoring watch and is flagged for QA sampling.
13. **Write the Investigation Note.** It renders the Case at this gate and holds no state of its own,
    on the **same element structure as the Triage Note** — it extends and updates that Note rather than
    mirroring it. The canonical list is
    [Detection & Analysis §2.6](references/framework/03-Processes/02-detection_and_analysis.md), in this
    order: **Summary** (as the Triage Note, at this gate); **Classification** (confirmed or last
    candidate category, severity, confidence, impact, and on a confirmed Incident its tactics and
    techniques, significance and cross-border, and the decision: the `verdict_id` the resolution produced, with the master Case id on a
    Duplicate; a near miss is `verdict_id` 2 at `severity_id` 1, and the Classification says so in words); **Rationale** (the score of each side, the Observations that carry the verdict, the
    retractions and why — how the confidence was reached, not a restatement of it; on a near miss, the
    Observations that show nothing reached the environment); **Observations** (the
    Alerts; the triage Observations, each now verified or **retracted** with the reason; and the result of
    each validation query — every one rendered with its tag, with what produced it, and with the events
    it rests on by OCSF identifier; a Malicious Observation renders the techniques it shows; the Alerts
    also render what their detection asserted, as in the
    Triage Note, with the remediation state of each entity **as it stands at this gate**, and any
    recommended action run at this gate renders as the Observation it produced);
    **Re-classification Pivots**; **Case Timeline** (whatever the verdict: the one triage compiled, extended by
    what this investigation established; `timeline.py` on this ledger builds it); **Response Actions** (as the Triage Note, at this
    gate: the remediation the Case references and the open tickets it raised, with their kinds — on a confirmed
    Incident this is what Response is handed, so a ticket awaiting approval renders as such); **Visibility Gaps** (or
    "None."); **Provenance**, with the preserved-evidence pointer once §3.3 preservation has happened.
    There is no Executed Queries element and no Evidence References element: a query that produced a
    Observation is that Observation's `analytic`, and the identifiers are cited with each Observation.
    `python3 scripts/note_elements.py --kind investigation --note note.json` prints the elements in
    order and checks the Note — the ledger, with one field per element beside it — against those rules, reporting
    what §2.6 requires as **failures**, which is the only thing it reports: the Note may not be written while one
    stands. It renders the structure and runs the
    checks; the content and the prose are yours ([rules/note-prose.md](rules/note-prose.md)). The rules
    binding the two judgment steps are [rules/verify.md](rules/verify.md) (the hypotheses and the choice
    of queries) and [rules/tag.md](rules/tag.md) (what the answers mean), given to any executor as they
    stand, as is [rules/reach.md](rules/reach.md) for the reach assessment of step 11 (`$language` in
    them is the language the deployment writes in).
    Preserve evidence per §3.3.
14. **Emit.** On a Confirmed Incident, the **Investigation → Response contract** of
    [Playbook Architecture §5](references/framework/04-Playbooks/playbook_architecture.md): the triage
    contract fields refined, plus `verdict_id` (2, at `severity_id` 2 to 5), `incident_category`, `reclassification_pivots` when the
    category changed, `impact_id`, `significant`, `cross_border`, `is_suspected_breach`,
    `attacks` (the Incident's techniques), the planned
    response actions (step 11), and `notes` carrying the Investigation Note. `start_time` is already on
    the Case and carries T0. A confirmed Incident stays In Progress: its status follows the gates of
    the response, Resolved at recovery complete (G6) and Closed when Phase 4 completes (G7). Then
    invoke the `zerosoc-response` skill. Stakeholder notification (§3.2) is the SOC
    Manager's responsibility and starts after confirmation.

## Governance

Just-in-time scope per query, Case-attributed calls, token metering per invocation
([Guardrails §1, §4](references/framework/07-Governance/agentic_guardrails.md)). The Note is what QA
sampling reviews ([Supervision §2](references/framework/07-Governance/agentic_supervision.md)): observations,
tags and resolution, not transcripts. In **shadow mode** (Supervision §4) compute and record the verdict
but apply nothing.

## Completion criteria and critical failures

Complete when the Case is resolved per §2.4, reach is assessed where Malicious was proven, the
Investigation Note is produced and the contract or the closure verdict, at `severity_id` 1, is emitted
(a Case On Hold is not complete: it waits for its answers), plus the playbook's category-specific criteria. The playbook's **Critical
Failures** void the run regardless of anything else; so does a verdict reached without a required query,
a closure that leaves a confirmed foothold, or a Note whose material observations lack event references.
