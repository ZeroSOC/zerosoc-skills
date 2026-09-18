# Security Policy

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Report it through GitHub's private vulnerability reporting on this repository:
**Security → Report a vulnerability**. That channel is private to the maintainers
until a fix is published.

Please include the affected skill or script and version, what an attacker can do,
and the smallest reproduction you have. If a proof of concept touches a tenant,
describe it rather than attaching real telemetry — see *Do not send us tenant
data* below.

We aim to acknowledge a report within 5 working days, and to agree a disclosure
timeline with you before anything is published. Credit is given unless you ask
otherwise.

## What is in scope

The skills are instructions and deterministic scripts that an agent host runs
against security telemetry. Alert and evidence content is attacker-influenced
input. In scope:

- **Prompt-injection paths**: content of an alert, an evidence row or a tool
  result that can steer a skill away from the framework's method, for example to
  a Benign close, to a response action, or to skipping a required check.
- **Rule scripts**: an input that makes a deterministic script (coverage rule,
  confidence, ledger, process chain) return a wrong decision, crash, or read or
  write outside the working directory it was given.
- **Response gating**: any way to reach a response action that the framework's
  authorization matrix says requires approval, without that approval.
- **Packaging**: a skill archive whose contents differ from the tree it was
  built from, or a reference that differs from the pinned framework commit.

Out of scope: vulnerabilities in the agent host, in the model, or in the tools a
host connects to (report those to their maintainers), and detection-quality
disagreements with a playbook (open a normal issue on the framework).

## Do not send us tenant data

Never attach real incident exports, evidence tables, hunting results, device
names, user principal names or tenant identifiers from a production environment
to a report, an issue or a pull request. Describe the shape of the data instead,
or reduce it to the fixtures under `tests/fixtures/`, which come from a lab built
for testing.

## Supported versions

Fixes are made on `main` and released as a new tag. Older tags are not patched.
