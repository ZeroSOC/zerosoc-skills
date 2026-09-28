#!/usr/bin/env python3
"""Package each skill directory as skills/<name>.zip (top-level folder <name>/), for hosts that take an archive.

Excludes caches and editor files. Run after tools/build_references.py so the archives match the pin.
`--check` reports an archive that no longer matches its directory instead of rebuilding it, and
exits 1: an archive a host installs is the skill only while it is the skill's tree.
"""
import os, sys, zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILLS = os.path.join(ROOT, "skills")
SKIP_DIRS = {"__pycache__", ".DS_Store"}


def tree(name):
    """The files the archive holds for a skill, as {archive path: bytes}."""
    base = os.path.join(SKILLS, name)
    out = {}
    for dp, dns, fns in os.walk(base):
        dns[:] = sorted(d for d in dns if d not in SKIP_DIRS)
        for fn in sorted(fns):
            if fn.endswith((".pyc",)) or fn in SKIP_DIRS:
                continue
            p = os.path.join(dp, fn)
            with open(p, "rb") as f:
                out[os.path.join(name, os.path.relpath(p, base))] = f.read()
    return out


def package(name):
    out = os.path.join(SKILLS, f"{name}.zip")
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for path, data in tree(name).items():
            z.writestr(path, data)
    print(f"{out}: {os.path.getsize(out)} bytes")


def stale(name):
    """The archive paths that differ from the skill's directory: missing, extra or changed."""
    out = os.path.join(SKILLS, f"{name}.zip")
    if not os.path.exists(out):
        return ["(no archive)"]
    with zipfile.ZipFile(out) as z:
        held = {i.filename: z.read(i.filename) for i in z.infolist() if not i.is_dir()}
    wanted = tree(name)
    return sorted((set(held) ^ set(wanted)) | {p for p in held if p in wanted and held[p] != wanted[p]})


if __name__ == "__main__":
    check = "--check" in sys.argv
    names = [a for a in sys.argv[1:] if not a.startswith("--")] or sorted(
        d for d in os.listdir(SKILLS) if os.path.isdir(os.path.join(SKILLS, d)))
    if not check:
        for n in names:
            package(n)
        sys.exit(0)
    failed = False
    for n in names:
        differ = stale(n)
        if differ:
            failed = True
            print(f"{n}.zip is stale: {len(differ)} path(s) differ, e.g. {', '.join(differ[:3])}")
    print("archives match their skills" if not failed else "run tools/package.py to rebuild")
    sys.exit(1 if failed else 0)
