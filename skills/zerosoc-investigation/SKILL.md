---
name: zerosoc-investigation
description: Investigate a promoted Case under the ZeroSOC Framework (Phase 2.b). Selects the Investigation and Response playbook by candidate Incident Category, verifies or retracts the triage findings, runs discriminating validation queries tagged Malicious or Benign with a confidence, resolves the verdict by score and coverage, and produces the Investigation Note plus the Investigation to Response contract or the closure verdict. Use for a Case promoted at triage or opened by threat hunting.
license: Apache-2.0
metadata:
  version: "0.1.0"
  framework: "zerosoc-framework@86a43c8 (main, 2026-09-15)"
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
  and the Case **token budget**; both are organization settings.

## Procedure

1. **Select the playbook and check visibility.** Use the candidate `incident_category` from the contract:
   `python3 scripts/select_playbook.py --category IC-01 --section Investigation --bindings zerosoc.capabilities.json`.
   It prints the version, the required data sources, the visibility gaps to record, and the Investigation
   section (hypotheses, validation queries with their outcome tags, re-classification pivots). If no
   playbook exists for the category at this framework pin, apply §2 directly with the category definition
   in [incident_categories.md](references/framework/02-Taxonomy/incident_categories.md).
2. **Start the ledger** `ledger.json` (format in `scripts/resolve.py`) from the Triage Note: every
   tagged Finding with its side, confidence, source artifact and event reference. Refine the two
   hypotheses to the Case (§2.1); competing explanations within a side are sub-hypotheses that score for
   their side.
3. **Verify or retract** each triage finding, starting from the conflict (§2.2.1). A finding that does
   not hold or does not apply to this Case is marked `retracted` with the reason; the score is
   recomputed. Aim the first discriminating queries at the findings that conflict.
4. **Run the validation queries** (§2.2.3). The playbook's queries are indicative: choose the applicable
   ones, add what the Case calls for, and seek evidence *against* the favoured side. Each query is a
   question; translate it into the query language of the bound tool through the capability binding.
   Queries must be discriminating and state the reading of both outcomes, so a negative result is
   evidence too (a clean hash is a `Benign` finding, not silence). Tag each result as the query's mapping
   prescribes (`Malicious (…)` if …, `Benign (…)` if …), or as context; decide by judgment only when a
   result fits neither stated outcome. Findings from the same telemetry artifact count once. Record
   every query run, listed or added, with its outcome and tag. Egress rule as in triage: indicators only.
5. **Mark coverage.** When the Benign explanation accounts for a Medium or High Malicious finding, set
   `covered: true` on it; uncovered Low Malicious findings never block a Benign verdict, they lower its
   confidence and are listed as residual observations.
6. **Resolve**: `python3 scripts/resolve.py ledger.json`. Malicious is proven at a score of 3 or more;
   Benign at 3 or more *and* every Medium or High Malicious finding retracted or covered; the verdict and
   confidence follow the §2.4 table (confidence is the strongest carrying finding, never an average; a
   visibility gap caps it at Medium). If neither side is proven, run the remaining discriminating
   queries; when the timebox or budget expires, set `timebox_expired` and let the script close as
   **Insufficient Data** (7) with a monitoring watch (`watch_until`; re-open on recurrence of the
   entities) and emit a visibility or tuning ticket. Never stop for doubt; never "escalate".
7. **Re-classify on evidence drift** (§2.2.5). If the objective differs from or exceeds the candidate
   category, change `incident_category`, re-run step 1 for the new playbook, carry every finding
   forward, and record the pivot and its reason in the Note. The classification stays provisional until
   promotion.
8. **Assign correctly.** The moment a Crown Jewel asset or a privileged identity enters the scope, the
   assignee becomes a human (`handover_reason`); keep running queries and proposing, the human decides.
9. **On Malicious proven** (§3.1): set `verdict_id = 2`; assign the definitive Incident Category and the
   observed techniques as `ID (Name)`; build the **Case Timeline** (course of action interleaved with
   detection and response actions, each entry timestamped in UTC with its event reference) and record
   **T0**, the earliest confirmed malicious event; confirm or assess `impact_id`, and whether the
   Incident is **significant** under NIS2 Article 23(3) and **cross-border**; run the **retrospective
   entity sweep** (Cases closed as False Positive or Benign in the last 90 days sharing the Incident's
   entities; every match is flagged for QA review, never dismissed); pass the scope to response. At Low
   confidence the Incident is still declared; every containment action then requires approval.
10. **On Benign proven**: `verdict_id` 1 (False Positive, plus a tuning ticket to Phase 1) or 5 (Benign,
    plus a Knowledge Base entry if the exception was unrecorded). A Low-confidence close carries a
    monitoring watch and is flagged for QA sampling.
11. **Write the Investigation Note** with the template and worked example in
    [investigation_note.md](references/framework/06-Deliverables/investigation_note.md): Classification &
    Assessment; Executed Queries (each with outcome and tag); Resolution Rationale (score of each side,
    the findings that carry it, the retractions and why, the resulting confidence); Re-classification
    Pivots; Case Timeline with T0; Evidence References (OCSF identifiers for every material finding);
    Visibility Gaps (or "None."); Provenance. Preserve evidence per §3.3.
12. **Emit.** On a Confirmed Incident, the **Investigation → Response contract** of
    [Playbook Architecture §5](references/framework/04-Playbooks/playbook_architecture.md): the triage
    contract fields refined, plus `verdict_id`, `incident_category`, `t0`, `timeline`, `impact_id`,
    `significant`, `cross_border`, `is_suspected_breach`, `handover_reason` when a handover occurred,
    the recommended containment, eradication and recovery actions from the playbook, and a reference to
    the Note. Then invoke the `zerosoc-response` skill. Stakeholder notification (§3.2) is the SOC
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
