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
  and the block is a response. It never makes a Benign observation. What stays open is how the entity
  arrived, what ran before it was stopped, and whether the same thing is elsewhere — aim the checks
  there, and at the entities the source left active.
- The source's recommended actions come with the Case as context. They are a procedure written
  for an alert type before anything was known about this Case, and they mix two kinds of
  instruction: checks, and response actions — isolate the device, reset the password, block the
  address. A response action is not triage's to perform and its result is not evidence. Use what
  bears on the Case, write what you ran as an observation like any other with the recommendation named
  in its `analytic`, and pass over the rest without writing anything down about it.
- Tag each result Malicious or Benign at Low, Medium or High as the playbook prescribes; a result
  that bears on neither side is context: it carries no side and no confidence.
- Every observation cites the alert ids or the event references that ground it. An observation that cannot
  be grounded is not written.
- An enrichment that returned nothing, an unknown verdict or an error is context, never a Benign
  observation. A Benign (High) observation is one that **explains** an alert, on evidence in the results.
- A Benign observation that explains an alert names the playbook condition it matched — one entry
  of the alert type's **False Positive conditions** (the detection misfired: the activity is not what
  its description says it is evidence of) or of its **Benign conditions** (that activity, authorized)
  — by its place in the list. Never label the kind yourself: the list a condition is in is what
  decides the verdict, and it is read off the playbook. An observation that fits no entry of either
  list still carries its side and confidence; it names nothing.
- Do not decide; do not write the alerts themselves as observations, they are already the first
  Malicious observations, and an observation that says of one alert what its detection asserted
  restates it and is not evidence beyond it. Cite what a reading rests on: the item of the alert's
  own evidence you read further, each alert you relate, the result you read; never guess the impact.
- Write the observation texts in $language. Write technique codes `ID (Name)` where the name is
  known; a bare identifier is rendered for you and is never a failure.
