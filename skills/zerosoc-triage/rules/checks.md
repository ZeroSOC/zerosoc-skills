# Rules that bind the executor running the triage checks

The method is the skill; these are the rules it is held to while it runs the playbook section's
checks over the enrichment results, tags each one and validates the severity. They are stated once
here, so that a human analyst reading the skill and a model reading a prompt are held to the same
words: whatever gives this text to an executor gives it as it stands, with the Case's data beside
it, and does not restate it.

`$language` stands for the language the deployment writes its Notes in. Whoever gives this text to an
executor puts that language in its place; read as it is, it means the language of the deployment.

- Read what the detections assert before the checks: the techniques, the threat name and family,
  what detected it, the source's description, and the remediation it already performed. Do not
  re-derive by enquiry what the source already stated; the checks refine, test or contradict it.
- A remediation the source performed is **not** an explanation of an alert: the behaviour happened
  and the block is a response. It never makes a Benign finding. What stays open is how the entity
  arrived, what ran before it was stopped, and whether the same thing is elsewhere — aim the checks
  there, and at the entities the source left active.
- The source's recommended actions are indicative: run the ones that bear on this Case. One you
  run is a finding like any other, naming the recommendation it came from and tagged on the evidence
  it returned; one you do not run is not written down at all.
- Tag each result Malicious or Benign at Low, Medium or High as the playbook prescribes; a result
  that bears on neither side is context: it carries no side and no confidence.
- Every finding cites the alert ids or the event references that ground it. A finding that cannot
  be grounded is not written.
- An enrichment that returned nothing, an unknown verdict or an error is context, never a Benign
  finding. A Benign (High) finding is one that **explains** an alert, on evidence in the results.
- A Benign finding names the playbook condition that applies: one of its **False Positive
  conditions** when the detection misfired, one of its **Benign conditions** when authorized
  activity legitimately matched it. They lead to different verdicts.
- Do not decide; do not write the alerts themselves as findings, they are already the first
  Malicious findings; never guess the impact.
- Write the finding texts in $language. Technique codes are always `ID (Name)`.
