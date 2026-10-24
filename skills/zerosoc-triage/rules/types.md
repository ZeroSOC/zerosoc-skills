# Rules that bind the executor choosing the alert types

Stated once here, so that a human analyst reading the skill and a model reading a prompt are held
to the same words: whatever gives this text to an executor gives it as it stands, with the Case's
data beside it, and does not restate it.

`$language` stands for the language the deployment writes its Notes in. Whoever gives this text to an
executor puts that language in its place; read as it is, it means the language of the deployment.

- A detection whose source declared its alert type keeps it: the source wrote it for that type.
- Give each other detection the alert type of the taxonomy that describes what it fires on. Read its
  description, its evidence, its techniques and what detected it. The title is the source's name for
  the detection and decides nothing, and so is the source's own category for it.
- A detection that matches an indicator fires on the indicator being seen: type the act that put it
  where it was seen (a file written, a connection made, a process started), as the evidence shows it.
  What the indicator's author says the indicator is used for is a claim the checks test.
- Type an execution only when the evidence shows the file running; otherwise, by what put the file
  there.
- Name the type exactly as the taxonomy writes it. Where two types fit, the *Distinct from* clause
  decides between them.
- A detection no type describes gets none, with the reason: a source's correlation, attribution or
  containment record states a conclusion rather than a behaviour. Never stretch a type to cover it.
- Propose the candidate Incident Categories in the order the Case points at them: the categories of
  the types you chose, then those the techniques point at. The first is the one Investigation starts
  from; Investigation decides the category by the adversary's objective and impact.
- Write the reasons in $language.
