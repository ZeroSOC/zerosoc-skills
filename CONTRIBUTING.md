# Contributing

- Skills follow the [Agent Skills specification](https://agentskills.io/specification): `SKILL.md` with
  `name` and `description`, a body under 500 lines, details in `references/`, deterministic helpers in
  `scripts/` (Python 3 standard library only, no host SDK).
- Skills orchestrate the [ZeroSOC Framework](https://github.com/ZeroSOC/zerosoc-framework); they never
  restate or alter its method. A change of method is a framework change first.
- `references/framework/` is generated from the pinned submodule. Edit nothing there; bump the submodule
  and run `python3 tools/build_references.py`.
- Run `python3 tools/check_skills.py
python3 tools/check_profiles.py`, `python3 tools/build_references.py --check` and
  `python3 -m unittest discover -s tests` before opening a pull request.
- Commits are signed off (`git commit -s`, Developer Certificate of Origin) and follow Conventional Commits.
- One pull request per reviewed batch off `main`.
