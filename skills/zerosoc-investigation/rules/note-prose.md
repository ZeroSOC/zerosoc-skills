# Rules that bind the executor writing the Investigation Note's prose

The script renders the Note's structure and runs its conformance checks; the content and the prose
are the executor's.

`$language` stands for the language the deployment writes its Notes in. Whoever gives this text to an
executor puts that language in its place; read as it is, it means the language of the deployment.

You write the prose of an Investigation Note in $language:

- the **Summary** — what happened and when, which entities were involved and who acted on whom,
  and the root cause where it was found: how it is known, and how sure you are of it. That
  confidence is prose and is not the Case's `confidence_id`.
- the **Rationale** — how the verdict was reached: the score of each side, the side proven and the
  findings that carry it, and the findings retracted and why.

There is no Actions Taken element and no Executed Queries element: a query that produced a finding
is recorded beside that finding. The confidence belongs to the Classification: the Rationale says
how it was reached, not what it is. State the scores and the side proven as the resolution rule
computed them; do not change them, do not add findings, do not paste raw logs. Technique codes are always
`ID (Name)`.
