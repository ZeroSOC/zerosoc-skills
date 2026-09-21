# ZeroSOC Skills

Agent Skills that execute the [ZeroSOC Framework](https://github.com/ZeroSOC/zerosoc-framework): portable,
host-neutral procedures for the operational loop of an autonomous or human-run SOC. Each skill follows the
[Agent Skills specification](https://agentskills.io/specification) and runs in any host that implements
it, and in any ZeroSOC platform implementation that vendors this repository.

The framework is the method; the skills sequence it. Deterministic rules (the coverage rule that closes or
promotes at triage, the score-and-coverage resolution of a verdict, the containment autonomy matrix) run
as small standard-library Python scripts, so the decision is computed the same way whoever the executor
is. Judgment stays where the framework leaves it: producing, tagging and retracting findings, translating
playbook questions into tool queries, writing the Notes.

## Skills

| Skill | Framework phase | Decides | Produces |
|---|---|---|---|
| [`zerosoc-triage`](skills/zerosoc-triage/SKILL.md) | 2.a Triage | Close (False Positive, Benign, Duplicate) or Promote, by the coverage rule | Triage Note, Triage → Investigation contract |
| [`zerosoc-investigation`](skills/zerosoc-investigation/SKILL.md) | 2.b Investigation | the verdict by score and coverage (True Positive, False Positive, Benign, Duplicate, Insufficient Data) | Investigation Note, Investigation → Response contract |
| [`zerosoc-response`](skills/zerosoc-response/SKILL.md) | 3 Incident Response | pre-authorized vs requires approval per action, under the autonomy matrix | contained, eradicated, recovered environment; Case timeline; notifications |

Those three are the **method skills**, and they know no source. Beside them sits one **tool skill** per
technology: [`zerosoc-defender-xdr`](skills/zerosoc-defender-xdr/SKILL.md) holds the expertise that makes
that source answer the framework's questions well, and its **source profile** — the one versioned home for
what its records mean, which the capability binding names and the method skills' scripts read.

Each skill directory is self-contained: `SKILL.md` (the procedure, under 200 lines), `references/framework/`
(the framework documents and playbooks it needs, copied verbatim from the pinned framework commit with
their directory layout preserved so links keep resolving) and, in a method skill, `scripts/`
(standard-library Python, no host SDK); a tool skill carries `source_profile.json` instead. The framework
commit is recorded in each skill's `metadata.framework`.

## Install

In an agent host that supports the Agent Skills specification, install from this repository (for example
with the `skills` CLI: `npx skills add ZeroSOC/zerosoc-skills`), or copy a skill directory into the host's
skills folder. Then place a **capability binding** `zerosoc.capabilities.json` in the working directory:
it maps the capability classes the skills ask for to the tools of your deployment and states which data
sources are available. See [capabilities/](capabilities/README.md).

## Layout

```
skills/<name>/SKILL.md            the skill (Agent Skills spec)
skills/<name>/references/         generated from framework/ — do not edit
skills/<name>/scripts/            deterministic helpers, Python 3 standard library
skills/<name>/rules/              the rules an executor is held to at a judgment step, in the framework's words
skills/<name>/source_profile.json a tool skill's source profile: what one technology's records mean
framework/                        the ZeroSOC Framework, git submodule pinned to a commit
capabilities/                     capability classes, binding schema, example and reference bindings,
                                  the schemas of a source profile and of a local override of one
tools/                            build (references generation) and checks
tests/                            unit tests for the scripts, built from the framework's worked examples
```

## Maintain

```
git submodule update --init                  # fetch the pinned framework
python3 tools/build_references.py            # regenerate references/ after bumping the pin
python3 tools/check_skills.py                # spec and portability lint
python3 tools/check_profiles.py              # every source profile against its schema and itself
python3 tools/check_profiles.py --bindings capabilities/zerosoc.capabilities.defender-for-business.json
python3 tools/build_references.py --check    # references up to date with the pin
python3 -m unittest discover -s tests        # script tests
python3 tools/package.py                     # rebuild skills/<name>.zip for hosts that take an archive
```

Versioning: a skills release conforms to one framework commit, recorded in `metadata.framework`. Bump the
submodule, regenerate, rerun the checks, bump `metadata.version` in every skill, add the entry to
[CHANGELOG.md](CHANGELOG.md), tag `v<version>`. Implementations pin a tag.

## Scope and status

The skills cover what the framework at the pinned commit publishes: at `b5f4966` that is the eight domain
triage playbooks, the fifteen Incident Category playbooks plus the catch-all, and the five shared
enrichment sub-playbooks, all `draft`. Where a future pin lacks a playbook, the skill says so and applies
the method directly. Status `draft`, like the framework documents they execute.

## License

Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). The framework content under
`skills/*/references/framework/` is reproduced from the ZeroSOC Framework under the same license.
"ZeroSOC" is a claimed trademark of the project's Trademark Steward; see the framework's `TRADEMARKS.md`.
