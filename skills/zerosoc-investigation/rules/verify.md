# Rules that bind the executor refining the hypotheses and choosing the queries

Stated once here, so that a human analyst reading the skill and a model reading a prompt are held
to the same words: whatever gives this text to an executor gives it as it stands, with the Case's
data beside it, and does not restate it.

`$language` stands for the language the deployment writes its Notes in. Whoever gives this text to an
executor puts that language in its place; read as it is, it means the language of the deployment.

- Both hypotheses are always stated: the Malicious one (a threat actor) and the Benign one
  (administration, testing, scheduled or expected activity). Where the detection named a threat or
  a family, start the Malicious one there: a named family has documented behaviour, persistence and
  follow-on activity, so ask whether **those** are present rather than whether the activity is
  malicious in general. The name is a lead, not a verdict: retract it if the evidence does not
  support it.
- What the source already remediated explains nothing: the behaviour happened and the block is a
  response. It carries no side, and what stays open — how the entity arrived, what ran before it
  was stopped, whether the same thing is elsewhere — is what the queries must answer. An entity the
  source left active is where they go first.
- Start from the conflict: the findings that disagree are what the first queries must discriminate.
- A finding that does not hold, or does not apply to this Case, is retracted with its reason.
  Retract on evidence, not on doubt; a finding that merely cannot be confirmed still holds.
- Every query is discriminating and states both readings, so a negative result is evidence too (a
  clean hash is a Benign finding, not silence). A query whose negative result says nothing is not
  worth asking.
- The playbook's queries are indicative: choose the applicable ones and add what this Case calls
  for. Name the capability class that can answer each one; do not write any tool's query language.
- A question may be about an entity no alert cited, where the Case's own evidence names it: the
  host a command copied to, the address a script reached for. Scope stays inside the Case: an
  entity nothing in the Case mentions is not asked about.
- Ask only what the Case needs: the investigation's timebox and the Case's budget are finite, and
  both are the organization's settings.
- The kind of question decides which capability answers it; name the class the kind belongs to.
- Write in $language. Technique codes are always `ID (Name)`.
