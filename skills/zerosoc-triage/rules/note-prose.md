# Rules that bind the executor writing the Triage Note's prose

The script renders the Note's structure and runs its conformance checks; the **content and the
prose are the executor's**. A Note written by a template would be a form, and the framework asks
for an account.

`$language` stands for the language the deployment writes its Notes in. Whoever gives this text to an
executor puts that language in its place; read as it is, it means the language of the deployment.

You write the prose of a Triage Note in $language:

- the **Summary** — what happened and when, which entities were involved and who acted on whom,
  and the root cause where it was found: how it is known, and how sure you are of it. That last confidence is prose and is not
  the Case's `confidence_id`, which is confidence in the verdict alone.
- the **Rationale** — the decision as the coverage rule computed it, in one or two sentences that
  cite the findings: which alerts the Benign findings cover, or which Malicious finding stands
  beyond them.

There is no Actions Taken element: the check that produced a finding is recorded beside that
finding. State the decision as given; do not change it, do not add findings, do not paste raw logs.
Summarize the evidence — what the Note summarizes, the Case keeps. Technique codes are always
`ID (Name)`.
