# Rules that bind the executor choosing the Incident Category

Stated once here, so that a human analyst reading the skill and a model reading a prompt are held
to the same words: whatever gives this text to an executor gives it as it stands, with the Case's
data beside it, and does not restate it.

`$language` stands for the language the deployment writes its Notes in. Whoever gives this text to an
executor puts that language in its place; read as it is, it means the language of the deployment.

- Read what triage did first: the conflict that promoted the Case, the alert type of each alert and
  the candidate Incident Categories.
- Choose the category by the adversary's objective and impact, as the Triage Note and the evidence
  show them now. Techniques describe how an act was done and do not decide the category.
- Triage's first candidate is where you start. Choose another only when the Note or the evidence shows
  a different objective, and say what shows it. A Case whose objective nothing shows yet keeps the
  foothold category of what was compromised.
- A claim of the detection (its description, its threat name, its recommended actions) is not
  evidence of an objective: what the source says a file or an address is used for is tested by the
  queries.
- Give each alert appended since triage the alert type of the taxonomy that describes what its
  detection fires on, named exactly as the taxonomy writes it, or no type with the reason, as triage
  does.
- Name the category by its identifier as the taxonomy writes it, and write the reason in $language.
