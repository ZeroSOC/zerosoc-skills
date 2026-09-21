# Rules that bind the executor tagging what the validation queries returned

Stated once here, so that a human analyst reading the skill and a model reading a prompt are held
to the same words: whatever gives this text to an executor gives it as it stands, with the Case's
data beside it, and does not restate it.

`$language` stands for the language the deployment writes its Notes in. Whoever gives this text to an
executor puts that language in its place; read as it is, it means the language of the deployment.

- Tag by the outcomes the playbook states for that query — `→ Malicious (High) if <result>;
  Benign (Low) if <result>` — each with its confidence. Decide by judgment only when a result fits
  neither stated outcome; then it is usually context.
- A query that was not run, or whose answer says the source could not answer, produces **no**
  finding: it is a visibility gap, never a Benign finding.
- Evidence that **explains** what the alerts fired on is a Benign finding, not context. The Benign
  hypothesis is proven by evidence, like the Malicious one: a record of authorization is one way to
  prove it, and the absence of such a record proves nothing either way. When an answer shows what
  the activity actually was — the tooling it ran, what launched it, the artifacts it left — tag it
  Benign at the confidence the evidence carries, and say which alerts it explains.
- Activity that names itself is evidence, and it is weighed, not taken: an intruder can name
  themselves anything. What corroborates a declared explanation is the fit of the whole picture —
  every alerted action belonging to it, the artifacts and paths being the ones it uses, what
  launched it being what that activity is launched by — and above all **nothing outside it**. State the
  corroboration, and answer the question that settles it: did anything happen that the declared
  explanation does not account for? If something did, the explanation does not hold; if nothing
  did, say so, because that is the finding the verdict rests on.
- An answer with no rows **is** an answer: tag it as the playbook states for that outcome.
- Name the telemetry artifact a finding rests on, so two findings on the same artifact count once.
- Every Malicious finding at Medium or High left uncovered is stated, with the reason it stands.
  (*Residual* is the framework's word for the uncovered **Low** ones, below.) Consider
  each one against the explanation first: a detection's own wording is its reading of the
  behaviour, not a fact — where the evidence shows the behaviour was part of the explained
  activity, the finding is covered and the detection's reading was wrong. Where the evidence does
  not reach it, say so, and the Case stays an Incident on that finding.
- Coverage (§2.4): mark a Malicious finding covered when the Benign explanation accounts for that
  specific finding on evidence. Do not mark one covered because a verdict would be tidier, and do
  not leave one uncovered that the evidence plainly accounts for: the first invents a Benign
  verdict, the second invents an Incident. Uncovered Low Malicious findings do not block a Benign
  verdict; they are residual observations.
- Re-classify only on evidence: change the Incident Category when the objective differs from or
  exceeds the candidate one, and say why.
- Never state a verdict, a score or a confidence for the Case: the resolution rule computes them.
- Write in $language. Technique codes are always `ID (Name)`.
