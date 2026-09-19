---
name: zerosoc-investigation
description: Investigate a promoted Case under the ZeroSOC Framework (Phase 2.b). Selects the Investigation and Response playbook by candidate Incident Category, verifies or retracts the triage findings, runs discriminating validation queries tagged Malicious or Benign with a confidence, resolves the verdict by score and coverage, and produces the Investigation Note plus the Investigation to Response contract or the closure verdict. Use for a Case promoted at triage or opened by threat hunting.
license: Apache-2.0
metadata:
  version: "0.3.0"
  framework: "zerosoc-framework@5f4ab24 (main, 2026-09-18)"
  status: draft
  author: ZeroSOC
---

# ZeroSOC Investigation (Phase 2.b)

Object: the **hypothesis**. Two sides, always: the Malicious hypothesis (a threat actor) and the Benign
hypothesis (administration, testing, scheduled or expected activity). Outcome: exactly one of a **Closed
Case** or a **Confirmed Incident**. Verdicts are computed from tagged findings, not argued. Paths are
relative to this skill's directory.

Read once per session: [Detection & Analysis §2–§3](references/framework/03-Processes/02-detection_and_analysis.md)
and the confidence table in [Definitions §7](references/framework/01-Foundation/definitions.md). Read
per Case: the playbook the script prints.

## When to use

- A Case promoted at triage, carrying the Triage → Investigation contract and its Triage Note.
- A Case opened by threat hunting (§4.3): it enters here directly and is by definition a detection
  false negative.
- Not for alerts without a Case or a Triage Note: run the `zerosoc-triage` skill first.

## Inputs

- The promoted Case and contract; the Triage Note with its tagged Findings, which **seed the score** and
  are verified, not re-collected. The Note also carries the conflict that promoted the Case: the
  Malicious findings beyond the alerts and the Benign findings they were weighed against.
- The capability binding `zerosoc.capabilities.json`; the telemetry classes (`telemetry.endpoint`,
  `telemetry.identity`, `telemetry.network`, `telemetry.email`, `telemetry.cloud`, `siem.search`), the
  enrichment classes and `cases.store`.
- The investigation **timebox** (10 minutes at High or Critical severity, 20 otherwise, reference values)
  and the Case **token budget**; both are organization settings. `scripts/resolve.py` measures the
  timebox from the ledger's timestamps.

## Procedure

1. **Select the playbook and check visibility.** Use the candidate `incident_category` from the contract:
   `python3 scripts/select_playbook.py --category IC-01 --section Investigation --bindings zerosoc.capabilities.json`.
   It prints the version, the required data sources, the visibility gaps to record, and the Investigation
   section (hypotheses, validation queries with their outcome tags, re-classification pivots). Record the
   selection in the ledger (`playbook`, `playbook_version`, `incident_category`), and again after a
   re-classification pivot: the Note's Provenance repeats it. If no
   playbook exists for the category at this framework pin, apply §2 directly with the category definition
   in [incident_categories.md](references/framework/02-Taxonomy/incident_categories.md).
2. **Extract the evidence inventory** for the Case as it is now: alerts are appended after triage, so the
   triage inventory is a starting point, not the answer. List every entity the source attaches to the
   Case's alerts as `evidence.json` and run
   `python3 scripts/evidence_inventory.py evidence.json --source-count N` (N: the evidence items the source
   shows). Record the printed `evidence_inventory` object in the ledger; extract what is missing before
   scoring. For a hunt-opened Case the inventory is what the hunt collected, and N is unverified.
   When it holds processes, rebuild the lineage with `python3 scripts/process_chain.py evidence.json --alerts alerts.json`
   (one chain per alert, each process under its ancestors; `--case` joins them into one chain per device, the
   view to score on). Where the bound endpoint class carries process telemetry, query the Case's devices and
   window for process creations and pass them with `--telemetry telemetry.json`: the ancestors the alerts never
   cited are reconstructed and marked as such. Where it carries alert evidence only, the chain stops at the
   first ancestor no alert cited: that is a **lineage gap**, it is recorded, and no hypothesis may rest on a
   lineage the evidence does not show. Command lines, their decodings and the remediation state of each process
   are findings in their own right, not decoration, and so is the number of layers a command was encoded
   in: decoding stops at five rounds, and a command still encoded there is recorded as such.
3. **Start the ledger** `ledger.json` (format in `scripts/resolve.py`) from the Triage Note: every
   tagged Finding with its side, confidence, source artifact and event reference. Record `started_at`
   (UTC) now, the Case `severity`, the `evidence_inventory` object of step 2, and `at` on every finding
   as it is added: the timebox is computed from these, not declared. Alert findings carry their
   `alert_type` and `entity`, so the same type on the same entity counts once in the score; alerts
   appended since triage are added with `python3 scripts/alert_types.py alerts.json --bindings zerosoc.capabilities.json --json`,
   whose entries are ready-made Malicious findings. Refine the two
   hypotheses to the Case (§2.1); competing explanations within a side are sub-hypotheses that score for
   their side.
4. **Verify or retract** each triage finding, starting from the conflict (§2.2.1). A finding that does
   not hold or does not apply to this Case is marked `retracted` with the reason; the score is
   recomputed. Aim the first discriminating queries at the findings that conflict.
5. **Run the validation queries** (§2.2.3). The playbook's queries are indicative: choose the applicable
   ones, add what the Case calls for, and seek evidence *against* the favoured side. Each query is a
   question; translate it into the query language of the bound tool through the capability binding.
   Queries must be discriminating and state the reading of both outcomes, so a negative result is
   evidence too (a clean hash is a `Benign` finding, not silence). Tag each result as the query's mapping
   prescribes (`Malicious (…)` if …, `Benign (…)` if …), or as context; decide by judgment only when a
   result fits neither stated outcome. Findings from the same telemetry artifact count once. Record
   every query run, listed or added, with its outcome and tag. Egress rule as in triage: indicators only.
6. **Mark coverage.** When the Benign explanation accounts for a Medium or High Malicious finding, set
   `covered: true` on it; uncovered Low Malicious findings never block a Benign verdict, they lower its
   confidence and are listed as residual observations.
7. **Resolve**: set `resolved_at` (UTC) in the ledger and run `python3 scripts/resolve.py ledger.json`. Malicious is proven at a score of 3 or more;
   Benign at 3 or more *and* every Medium or High Malicious finding retracted or covered; the verdict and
   confidence follow the §2.4 table (confidence is the strongest carrying finding, never an average). If neither side is proven, run the remaining discriminating
   queries. The script measures the timebox from `started_at` to `resolved_at` (the current time when absent)
   against the severity-scaled reference value, which `timebox_minutes` may tighten, never extend; when it has expired, or the
   budget is exhausted (`budget_exhausted`), it closes as **Insufficient Data** (7) with a monitoring watch (`watch_until`; re-open on recurrence of the
   entities) and emit a visibility or tuning ticket. Never stop for doubt; never "escalate".
8. **Re-classify on evidence drift** (§2.2.5). If the objective differs from or exceeds the candidate
   category, change `incident_category`, re-run step 1 for the new playbook, carry every finding
   forward, and record the pivot and its reason in the Note. The classification stays provisional until
   promotion.
9. **Assign correctly.** The moment a Crown Jewel asset or a privileged identity enters the scope, the
   assignee becomes a human (`handover_reason`); keep running queries and proposing, the human decides.
10. **On Malicious proven** (§3.1): set `verdict_id = 2`; assign the definitive Incident Category and the
    observed techniques as `ID (Name)`; build the **Case Timeline** (the course of the attack interleaved
    with detection and response actions, each entry timestamped in UTC with its event reference; the
    `timeline` of `process_chain.py --json` gives the process entries with their alerts as references).
    The timeline is not a field the Case stores: it is the Findings flagged `zerosoc:timeline`, rendered
    in `first_seen_time` order. The Case's `start_time` opens at the earliest Alert and moves earlier
    whenever a Malicious Finding cites an earlier event; on a confirmed Incident it is **T0**, the
    earliest confirmed malicious event. Confirm or assess `impact_id`, and whether the
    Incident is **significant** under NIS2 Article 23(3) and **cross-border**; run the **retrospective
    entity sweep** through the `cases.store` capability class (Cases closed as False Positive or Benign
    in the last 90 days sharing the Incident's entities; never through `telemetry.*`, whose retention is
    shorter than the window; an unbound `cases.store` is a visibility gap; every match is flagged for QA
    review, never dismissed); pass the scope to response. At Low
    confidence the Incident is still declared; every containment action then requires approval.
11. **On Benign proven**: `verdict_id` 1 (False Positive, plus a tuning ticket to Phase 1) or 5 (Benign,
    plus a Knowledge Base entry if the exception was unrecorded). A Low-confidence close carries a
    monitoring watch and is flagged for QA sampling.
12. **Write the Investigation Note.** It renders the Case at this gate and holds no state of its own,
    on the **same element structure as the Triage Note** — it extends and updates that Note rather than
    mirroring it. The canonical list is
    [Detection & Analysis §2.5](references/framework/03-Processes/02-detection_and_analysis.md), in this
    order: **Classification** (confirmed or last candidate category, severity, confidence, impact,
    significance and cross-border on a confirmed Incident, and the decision: the `verdict_id` the
    resolution produced, with the master Case id on a Duplicate); **Summary** (as the Triage Note, at
    this gate); **Findings** (the Alerts; the triage Findings, each now verified or **retracted** with
    the reason; and the result of each validation query — every one rendered with its tag, with what
    produced it, and with the events it rests on by OCSF identifier); **Rationale** (the score of each
    side, the Findings that carry the verdict, the retractions and why — how the confidence was reached,
    not a restatement of it); **Re-classification Pivots**; **Case Timeline**; **Visibility Gaps** (or
    "None."); **Provenance**, with the preserved-evidence pointer once §3.3 preservation has happened.
    There is no Executed Queries element and no Evidence References element: a query that produced a
    Finding is that Finding's `analytic`, and the identifiers are cited with each Finding.
    Preserve evidence per §3.3.
13. **Emit.** On a Confirmed Incident, the **Investigation → Response contract** of
    [Playbook Architecture §5](references/framework/04-Playbooks/playbook_architecture.md): the triage
    contract fields refined, plus `verdict_id`, `incident_category`, `reclassification_pivots` when the
    category changed, `impact_id`, `significant`, `cross_border`, `is_suspected_breach`,
    `handover_reason` when a handover occurred, the recommended containment, eradication and recovery
    actions from the playbook, and `notes` carrying the Investigation Note. `start_time` is already on
    the Case and carries T0. Then invoke the `zerosoc-response` skill. Stakeholder notification (§3.2) is the SOC
    Manager's responsibility and starts after confirmation.

## Governance

Just-in-time scope per query, Case-attributed calls, token metering per invocation
([Guardrails §1, §5](references/framework/07-Governance/agentic_guardrails.md)). The Note is what QA
sampling reviews ([Supervision §2](references/framework/07-Governance/agentic_supervision.md)): findings,
tags and resolution, not transcripts. In **shadow mode** (Supervision §4) compute and record the verdict
but apply nothing.

## Completion criteria and critical failures

Complete when the Case is resolved per §2.4, the Investigation Note is produced and the contract or the
closure verdict is emitted, plus the playbook's category-specific criteria. The playbook's **Critical
Failures** void the run regardless of anything else; so does a verdict reached without a required query,
a closure that leaves a confirmed foothold, or a Note whose material findings lack event references.
