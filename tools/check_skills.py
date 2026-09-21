#!/usr/bin/env python3
"""Lint the skills against the Agent Skills specification and this repo's portability rules.

Checks: directory name == frontmatter name; name pattern; description length and no angle brackets
in frontmatter; body under 500 lines; every referenced local path exists; no host-specific idioms;
public-safety (no internal codenames). Exit 1 on any failure.
"""
import os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
CODENAME = "Or" + "ob"  # internal codename that must never appear in a public-bound repository
FORBIDDEN_BODY = [r"(?<![\w/])/zerosoc[-\w]*\b", r"\bClaude Code\b", r"\b" + CODENAME + r"\b"]
FORBIDDEN_FM = ["<", ">", CODENAME]


def parse_frontmatter(text):
    assert text.startswith("---\n"), "missing frontmatter"
    end = text.find("\n---\n", 4)
    assert end != -1, "unterminated frontmatter"
    fm = text[4:end]
    body = text[end + 5:]
    fields = {}
    key = None
    for line in fm.splitlines():
        m = re.match(r"^([A-Za-z_-]+):\s*(.*)$", line)
        if m and not line.startswith(" "):
            key = m.group(1)
            fields[key] = m.group(2).strip()
        elif key and line.startswith(" "):
            fields[key] = (fields[key] + " " + line.strip()).strip()
    return fm, fields, body


def check_skill(base):
    """The failures of one skill directory. Prints its one-line summary when it has a readable SKILL.md."""
    failures, skill = [], os.path.basename(os.path.normpath(base))
    path = os.path.join(base, "SKILL.md")
    if not os.path.isfile(path):
        return [f"{skill}: no SKILL.md"]
    text = open(path, encoding="utf-8").read()
    try:
        fm, fields, body = parse_frontmatter(text)
    except AssertionError as e:
        return [f"{skill}: {e}"]
    name = fields.get("name", "")
    if name != skill: failures.append(f"{skill}: frontmatter name '{name}' != directory name")
    if not NAME_RE.match(name) or len(name) > 64: failures.append(f"{skill}: invalid name '{name}'")
    desc = fields.get("description", "").strip("'\"")
    if not desc: failures.append(f"{skill}: missing description")
    if len(desc) > 1024: failures.append(f"{skill}: description {len(desc)} chars > 1024")
    for ch in FORBIDDEN_FM:
        if ch in fm: failures.append(f"{skill}: frontmatter contains forbidden text '{ch}'")
    n = len(body.splitlines())
    if n > 500: failures.append(f"{skill}: body {n} lines > 500")
    # the rule text a skill ships is read by the same executors as its body, and is held to the same
    read = {"SKILL.md": body}
    rules = os.path.join(base, "rules")
    for fn in sorted(os.listdir(rules)) if os.path.isdir(rules) else []:
        if fn.endswith(".md"):
            read[f"rules/{fn}"] = open(os.path.join(rules, fn), encoding="utf-8").read()
    for where, held in read.items():
        here = os.path.join(base, os.path.dirname(where))  # a link is followed from the file that writes it
        for pat in FORBIDDEN_BODY:
            for m in re.finditer(pat, held):
                failures.append(f"{skill}: host-specific or non-public-safe text '{m.group(0)}' in {where}")
        # in SKILL.md, the links into the skill's own folders; in a rule file, every link that is not a web address
        links = r"\]\(((?:references|scripts|rules)/[^)#\s]+)" if where == "SKILL.md" else r"\]\((?![a-z]+:|#)([^)#\s]+)"
        for m in re.finditer(links, held):
            if not os.path.exists(os.path.normpath(os.path.join(here, m.group(1)))):
                failures.append(f"{skill}: missing referenced path {m.group(1)} in {where}")
        for m in re.finditer(r"`(scripts/[\w./-]+\.py)`|python3 (scripts/[\w./-]+\.py)", held):
            rel = m.group(1) or m.group(2)
            if not os.path.exists(os.path.join(base, rel)):
                failures.append(f"{skill}: missing script {rel} in {where}")
    for name in read:
        if name != "SKILL.md" and not any(os.path.basename(name) in held for where, held in read.items() if where != name):
            failures.append(f"{skill}: {name} is linked from nowhere in the skill, so no executor is sent to it")
    print(f"{skill}: ok ({n} body lines, description {len(desc)} chars)")
    return failures


def main():
    failures = []
    skills_dir = os.path.join(ROOT, "skills")
    for skill in sorted(os.listdir(skills_dir)):
        base = os.path.join(skills_dir, skill)
        if os.path.isdir(base):  # packaged archives and stray files are not skills
            failures += check_skill(base)
    for dp, _, fns in os.walk(ROOT):
        if ".git" in dp or os.path.join(ROOT, "framework") in dp: continue
        for fn in fns:
            if fn.endswith((".md", ".py", ".json", ".yml")):
                if CODENAME in open(os.path.join(dp, fn), encoding="utf-8", errors="ignore").read():
                    failures.append(f"public-safety: codename in {os.path.relpath(os.path.join(dp, fn), ROOT)}")
    if failures:
        print("\n".join("FAIL " + f for f in failures)); sys.exit(1)
    print("all checks passed")


if __name__ == "__main__":
    main()
