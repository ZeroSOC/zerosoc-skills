#!/usr/bin/env python3
"""Package each skill directory as skills/<name>.zip (top-level folder <name>/), for hosts that take an archive.

Excludes caches and editor files. Run after tools/build_references.py so the archives match the pin.
"""
import os, sys, zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILLS = os.path.join(ROOT, "skills")
SKIP_DIRS = {"__pycache__", ".DS_Store"}


def package(name):
    base = os.path.join(SKILLS, name)
    out = os.path.join(SKILLS, f"{name}.zip")
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for dp, dns, fns in os.walk(base):
            dns[:] = sorted(d for d in dns if d not in SKIP_DIRS)
            for fn in sorted(fns):
                if fn.endswith((".pyc",)) or fn in SKIP_DIRS:
                    continue
                p = os.path.join(dp, fn)
                z.write(p, os.path.join(name, os.path.relpath(p, base)))
    print(f"{out}: {os.path.getsize(out)} bytes")


if __name__ == "__main__":
    names = sys.argv[1:] or sorted(d for d in os.listdir(SKILLS) if os.path.isdir(os.path.join(SKILLS, d)))
    for n in names:
        package(n)
