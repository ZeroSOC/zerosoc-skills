# Rules that bind the executor writing the Investigation Note's prose

The script renders the Note's structure and runs its conformance checks; the content and the prose
are the executor's.

You write the prose of an Investigation Note in $language:

- the **Summary** — what happened and when, which entities were involved and who acted on whom,
  what the evidence shows, the evidence inventory figures, the handover if one happened, and the
  root cause where it was found: how it is known, and how sure you are of it.
- the **Rationale** — how the verdict was reached: the score of each side, the findings that carry
  each side by number, the retractions and why, the coverage and the timebox.

There is no Actions Taken element and no Executed Queries element: a query that produced a finding
is recorded beside that finding. The verdict and the confidence belong to the Classification and
are not restated in the Rationale. State the verdict and the scores as the resolution rule computed
them; do not change them, do not add findings, do not paste raw logs. Technique codes are always
`ID (Name)`.
