#!/usr/bin/env python3
"""Generate each skill's references/framework/ tree from the pinned framework submodule.

Files are copied verbatim, preserving the framework's directory layout so that the relative links
inside them keep resolving. A provenance line is inserted after the YAML frontmatter. Shared scripts
listed in the manifest are copied from tools/shared/ into the skill's scripts/ directory.

Usage:
  python3 tools/build_references.py          # (re)generate
  python3 tools/build_references.py --check  # exit 1 if the generated tree is stale
"""
import glob, hashlib, json, os, shutil, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = json.load(open(os.path.join(ROOT, "tools", "references_manifest.json")))
FW = os.path.join(ROOT, MANIFEST["framework_dir"])


def framework_commit():
    out = subprocess.run(["git", "-C", FW, "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
    return out.stdout.strip()


def stamp(text, rel, commit):
    line = f"<!-- generated from zerosoc-framework@{commit[:12]} : {rel} — do not edit; regenerate with tools/build_references.py -->\n"
    if text.startswith("---\n"):
        end = text.find("\n---\n", 4)
        if end != -1:
            end += len("\n---\n")
            return text[:end] + line + text[end:]
    return line + text


def expected_tree(skill, spec, commit):
    files = list(MANIFEST["common"]) + list(spec.get("files", []))
    for g in spec.get("globs", []):
        for path in sorted(glob.glob(os.path.join(FW, g))):
            rel = os.path.relpath(path, FW)
            if os.path.basename(rel) == "_TEMPLATE.md" or rel in files:
                continue
            files.append(rel)
    out = {}
    for rel in files:
        src = os.path.join(FW, rel)
        if not os.path.exists(src):
            print(f"warning: {rel} not in framework at {commit[:12]}; skipped", file=sys.stderr)
            continue
        data = open(src, encoding="utf-8").read()
        out[os.path.join("references", "framework", rel)] = stamp(data, rel, commit) if rel.endswith(".md") else data
    manifest_md = [f"# Generated framework references\n", f"Source: zerosoc-framework@{commit} (Apache-2.0).\n", "Do not edit these files; regenerate with `python3 tools/build_references.py`.\n", ""]
    for rel in sorted(k for k in out):
        manifest_md.append(f"- `{rel}`")
    out[os.path.join("references", "framework", "MANIFEST.md")] = "\n".join(manifest_md) + "\n"
    for name in spec.get("shared_scripts", []):
        out[os.path.join("scripts", name)] = open(os.path.join(ROOT, "tools", "shared", name), encoding="utf-8").read()
    return out


def main():
    check = "--check" in sys.argv
    commit = framework_commit()
    stale = []
    for skill, spec in MANIFEST["skills"].items():
        base = os.path.join(ROOT, "skills", skill)
        tree = expected_tree(skill, spec, commit)
        gen_dir = os.path.join(base, "references", "framework")
        if check:
            current = {}
            if os.path.isdir(gen_dir):
                for dp, _, fns in os.walk(gen_dir):
                    for fn in fns:
                        p = os.path.join(dp, fn)
                        current[os.path.relpath(p, base)] = open(p, encoding="utf-8").read()
            for name in spec.get("shared_scripts", []):
                p = os.path.join(base, "scripts", name)
                current[os.path.join("scripts", name)] = open(p, encoding="utf-8").read() if os.path.exists(p) else None
            if current != tree:
                stale.append(skill)
            continue
        if os.path.isdir(gen_dir):
            shutil.rmtree(gen_dir)
        for rel, data in tree.items():
            p = os.path.join(base, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as f:
                f.write(data)
        print(f"{skill}: {len(tree)} files at framework {commit[:12]}")
    if check:
        if stale:
            print("stale generated references in: " + ", ".join(stale))
            sys.exit(1)
        print("generated references are up to date")


if __name__ == "__main__":
    main()
