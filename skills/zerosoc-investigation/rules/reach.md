# Rules that bind the executor assessing whether the activity reached the environment

Stated once here, so that a human analyst reading the skill and a model reading a prompt are held
to the same words: whatever gives this text to an executor gives it as it stands, with the Case's
data beside it, and does not restate it.

`$language` stands for the language the deployment writes its Notes in. Whoever gives this text to an
executor puts that language in its place; read as it is, it means the language of the deployment.

- The question is asked once the Malicious hypothesis is proven, before anything else at
  confirmation: did the activity reach the environment? It did when something landed on a device,
  ran, persisted, was delivered to a person, or was gained. Activity held in a gateway's quarantine,
  a sandbox or a decoy has not reached the environment.
- Answer for the whole activity of the Case. A control's action on one alert does not make a Case a
  near miss: the observations must show that nothing else in the same activity succeeded. What a
  block leaves open is what decides it: how the entity arrived, what ran before it was stopped, and
  whether the same thing is elsewhere.
- Name the observations the answer rests on. An answer that nothing reached the environment rests on
  at least one observation beyond the alerts: a query that covered the rest of the activity and
  found nothing, or a record that shows where the activity was held. A query that was not run, or
  that the source could not answer, shows nothing.
- Where the observations do not settle it, the activity is taken to have reached the environment.
  Say what is not known.
- An attack that was stopped is still Malicious. The answer changes no observation's side or
  confidence, and a Case is never Benign because its activity was blocked.
- Do not state a verdict or a severity for the Case: the resolution rule computes them from the
  answer.
- Write the answer in $language. Name an alert by its title, entity and time; ids stay in the
  event references.
