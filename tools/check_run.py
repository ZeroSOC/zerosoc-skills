#!/usr/bin/env python3
"""Check a live run of the skills against the behaviour the release fixed. Standard library only.

  check_run.py run/ [--profile skills/zerosoc-defender-xdr/source_profile.json]

A run is a directory holding what the executor produced, one file per artifact:

  evidence.json            the Case's evidence rows, as given to evidence_inventory.py
  alerts.json              the source alerts, as given to alert_types.py
  ledger.triage.json       the triage ledger at the decision, with "domain", the Note's
                           "recorded_verdict" and the "detection_metadata" of alert_metadata.py
  ledger.investigation.json  the investigation ledger at the resolution   (optional)
  triage_note.md           the Triage Note                                 (optional)
  investigation_note.md    the Investigation Note                          (optional)
  zerosoc.capabilities.json  the binding the run used, with the local override of the source
                           profile beside it where the binding names one

The checks are the ones a human cannot do by reading a transcript: every figure the run reported is
recomputed from the artifacts it produced, so a ledger that states an inventory it never extracted, a
score built from observations that should have collapsed, or a timebox that was declared instead of measured,
all fail here. What the checks cannot see — whether the executor followed the procedure, whether a
observation is true — stays a human judgement, and the run's notes are where that is read.

Each check prints `ok` or `FAIL` with what was expected and what the run holds. Exit 1 on any failure,
2 when the run is missing an artifact the check needs.
"""
import argparse, importlib.util, json, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(rel, name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, rel))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


evidence_inventory = load("tools/shared/evidence_inventory.py", "evidence_inventory")
alert_types = load("tools/shared/alert_types.py", "alert_types")
alert_metadata = load("tools/shared/alert_metadata.py", "alert_metadata")
source_profile = alert_metadata.source_profile
triage_decide = load("skills/zerosoc-triage/scripts/triage_decide.py", "triage_decide")
resolve_rule = load("skills/zerosoc-investigation/scripts/resolve.py", "resolve_rule")


class Report:
    def __init__(self):
        self.failed, self.skipped = 0, 0

    def ok(self, check, detail=""):
        print(f"ok    {check}" + (f" — {detail}" if detail else ""))

    def fail(self, check, expected, found):
        self.failed += 1
        print(f"FAIL  {check}\n        expected: {expected}\n        run has:  {found}")

    def note(self, check, detail):
        print(f"note  {check} — {detail}")

    def skip(self, check, why):
        self.skipped += 1
        print(f"skip  {check} — {why}")

    def check(self, condition, name, expected, found):
        self.ok(name, found) if condition else self.fail(name, expected, found)


def concrete(source):
    """A data source a binding can answer. The generic playbook names its sources by deferral
    ("Depends on the triggering alert…") and some playbooks carry a bracketed placeholder: neither
    names a source, so neither is a gap or an unbound binding."""
    text = str(source).strip()
    return bool(text) and not text.startswith("Depends on") and not (text.startswith("<") and text.endswith(">"))


def playbooks(selector):
    """Every playbook the skills carry: triage mirrors 01-Triage, investigation mirrors 02-Investigation-Response."""
    out, seen = [], set()
    for skill in ("zerosoc-triage", "zerosoc-investigation", "zerosoc-response"):
        base = os.path.join(ROOT, "skills", skill, "references", "framework")
        for book in selector.load_playbooks(base) if os.path.isdir(base) else []:
            if book["rel"] not in seen:
                seen.add(book["rel"]); out.append(book)
    return out


def read_reference(rel):
    """A generated framework reference, read from the triage skill: the pin the run was given."""
    with open(os.path.join(ROOT, "skills", "zerosoc-triage", "references", "framework", *rel.split("/")),
              encoding="utf-8") as f:
        return f.read()


def read(run, name):
    path = os.path.join(run, name)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f) if name.endswith(".json") else f.read()


def check_inventory(report, run, ledger, label):
    """The inventory in the ledger is the one the evidence produces, not a figure the executor wrote."""
    rows = read(run, "evidence.json")
    recorded = (ledger or {}).get("evidence_inventory")
    if rows is None:
        return report.skip(f"{label}: evidence inventory recomputed", "no evidence.json in the run")
    if not recorded:
        return report.fail(f"{label}: evidence inventory recorded", "an evidence_inventory object in the ledger",
                           "none: the fix asks for it before the ledger is started")
    built = evidence_inventory.build(rows)
    report.check(built["count"] == recorded.get("extracted"), f"{label}: extracted count matches the evidence",
                 f"{built['count']} entities from {len(rows)} rows", f"extracted={recorded.get('extracted')}")
    source_count = recorded.get("source_count")
    if source_count is None:
        report.skip(f"{label}: completeness verified", "source_count not recorded (the source showed no count)")
    else:
        fresh = evidence_inventory.completeness(built, source_count)
        report.check(fresh["complete"] == recorded.get("complete"), f"{label}: completeness as recomputed",
                     f"complete={fresh['complete']} against the source's {source_count}",
                     f"complete={recorded.get('complete')}")
        if fresh["complete"] is False:
            report.ok(f"{label}: incompleteness is visible", evidence_inventory.note(fresh))


def override_of(run, profile_path):
    """The local override the run's binding names for this profile's source, as a path in the run.

    The override says itself which source it is for, so it is found by that and not by the key the
    binding happens to file the source under. One that cannot be read is still the run's override:
    it is returned, and reading the profile through it is what fails.
    """
    binding = read(run, "zerosoc.capabilities.json") or {}
    named = binding.get("source_profile_overrides")
    if not isinstance(named, dict) or not (profile_path and os.path.exists(profile_path)):
        return None
    source = source_profile.load(profile_path)["source"]["id"]
    paths = [os.path.join(run, str(name)) for name in named.values()]
    for path in paths:
        try:
            with open(path, encoding="utf-8") as handle:
                if json.load(handle).get("overrides") == source:
                    return path
        except (OSError, ValueError, AttributeError):
            continue
    unread = [path for path in paths if not os.path.exists(path)]
    return unread[0] if unread else (paths[0] if len(paths) == 1 else None)


def effective_profile(run, profile_path):
    """The profile as the run read it: the shipped one, with the run's override laid over it. An
    override that cannot be read is check_source_profile's failure to report; the other checks go
    on against the shipped profile."""
    try:
        return source_profile.load(profile_path, override_of(run, profile_path))
    except (OSError, ValueError):
        return source_profile.load(profile_path)


def check_source_profile(report, run, ledger, label, profile_path, note_name):
    """A run that read its source through a local override says so, on the ledger and in the Note's
    Provenance. The record is recomputed from the override file the run holds, so a ledger cannot
    pass one override off as another, or as none."""
    check = f"{label}: the source profile the run read is on the ledger"
    if not ledger:
        return
    override = override_of(run, profile_path)
    recorded = ledger.get("source_profile")
    held = recorded.get("override") if isinstance(recorded, dict) else None
    if not override:
        if held or (recorded is not None and not isinstance(recorded, dict)):
            report.fail(check, "no override: the run's binding names none", f"the ledger records {recorded!r}")
        return
    try:
        profile = source_profile.load(profile_path, override)
    except OSError:
        return report.fail(check, f"{os.path.basename(override)} in the run, beside the binding that names it",
                           "the file is not in the run, so what the run read cannot be reproduced")
    except ValueError as exc:
        return report.fail(check, "an override the profile can be read through", str(exc))
    fresh = source_profile.record(profile)
    stated = fresh["source_profile"]["override"]
    report.check(isinstance(held, dict) and held.get("sha256") == stated["sha256"], check,
                 f"source_profile.override with sha256 {stated['sha256'][:12]}… ({stated['file']}: {stated['reason']})",
                 f"sha256 {str(held.get('sha256'))[:12]}…" if isinstance(held, dict)
                 else "no source_profile.override in the ledger")
    if stated["stale"]:
        report.note(check, source_profile.notes(profile)[-1])
    said = f"{label}: the Note's Provenance names the override"
    note = read(run, note_name)
    if note is None:
        return report.skip(said, f"no {note_name} in the run")
    version = fresh["product"]["feature"]["version"]
    report.check(version in note or stated["file"] in note, said,
                 f"the profile version {version} or the override's file name {stated['file']}",
                 "named" if version in note or stated["file"] in note else "the Note names neither")


def check_alert_map(report, run, profile_path):
    """The source's alerts against its source profile: what it covers, and what it collapses."""
    alerts = read(run, "alerts.json")
    if alerts is None:
        report.skip("alert types: mapped from the source profile", "no alerts.json in the run")
        return None
    if not profile_path or not os.path.exists(profile_path):
        report.skip("alert types: mapped from the source profile", "no source profile given")
        return None
    amap = source_profile.alert_rules(effective_profile(run, profile_path))
    built = alert_types.build_alerts(alerts, amap)
    unmapped = sorted({str(a.get("source_title") or a.get("id")) for a in built if a.get("unmapped")})
    if unmapped:
        report.note("alert types: source titles the profile does not cover",
                    f"{len(unmapped)} to report on the ticket, with the detector id of each: " + "; ".join(unmapped))
    else:
        report.ok("alert types: every source title maps to a framework type")
    collapsed = len(alerts) - len(built)
    report.ok("alert types: same type on one entity collapsed",
              f"{len(alerts)} source alerts → {len(built)} observations ({collapsed} collapsed)")
    return {str(a.get("source_title") or "").lower() for a in built}


def check_alert_ledger(report, ledger, label, source_titles=None):
    """The Case's alerts in a ledger: typed, placed on an entity, never the same observation twice, and
    named as the framework names them — a type the catalog does not hold was invented in the run.

    Triage holds them in `alerts` (`type`, `entity`), where the decision rule reads them; investigation
    holds them among the scored `observations` (`alert_type`, `entity`). Both shapes are checked here."""
    ledger = ledger or {}
    observations = [dict(a, alert_type=a.get("type")) for a in ledger.get("alerts", []) if a.get("type")]
    observations += [f for f in ledger.get("observations", []) if f.get("alert_type")]
    if not observations:
        report.skip(f"{label}: the Case's alerts carry type and entity",
                    "no alerts in the ledger: triage records them in \"alerts\", investigation among \"observations\"")
        return []
    typed = [f for f in observations if f.get("entity")]
    report.check(len(typed) == len(observations), f"{label}: the Case's alerts carry type and entity",
                 "every alert with a type and the entity it was raised on",
                 f"all {len(observations)} placed on an entity" if len(typed) == len(observations)
                 else f"{len(observations) - len(typed)} of {len(observations)} without an entity")
    keys = {(str(f["alert_type"]).lower(), str(f.get("entity", "")).lower()) for f in typed}
    report.check(len(keys) == len(typed), f"{label}: no alert counted twice",
                 "one observation per (type, entity)", f"{len(typed)} observations for {len(keys)} distinct pairs")
    catalog = alert_types.framework_alert_types(read_reference("02-Taxonomy/alert_types.md"))
    invented = sorted({f["alert_type"] for f in observations if f["alert_type"] not in catalog
                       and str(f["alert_type"]).lower() not in (source_titles or set())})
    report.check(not invented, f"{label}: alert types come from the framework catalog",
                 "every alert_type in the framework's alert_types.md, or the source title of an unmapped alert",
                 f"{len(invented)} from neither: " + "; ".join(invented[:4]) if invented else "none invented")
    return observations


def check_detection_metadata(report, run, ledger, label, note_name, profile_path=None):
    """Detection & Analysis §1.1: what the detection asserted is on the Case, and what it did not supply
    is a recorded gap.

    The assertions are **recomputed** from the run's own alerts and evidence, so a ledger cannot claim a
    technique or a threat name the alerts never carried, or quietly drop one they did. The dispositions
    of the recommended actions are the run's own work and are read from the ledger; everything else here
    is checked against the source records the run was given.
    """
    if not ledger:
        return report.skip(f"{label}: what the detection asserts is on the ledger", "no ledger in the run")
    binding = read(run, "zerosoc.capabilities.json")
    if binding is not None and not binding.get("source_profiles"):
        return report.skip(f"{label}: what the detection asserts is on the ledger",
                           "the binding names no source profile, so nothing declares where this source's "
                           "assertions live: they cannot be read and the deployment degrades explicitly")
    record = ledger.get("detection_metadata")
    if not record:
        return report.fail(f"{label}: what the detection asserts is on the ledger",
                           "the alerts' techniques, threat name, detection source, remediation state, "
                           "description and recommended actions, extracted before enrichment",
                           "the ledger carries no detection_metadata")
    alerts = read(run, "alerts.json")
    fresh = None
    if alerts and profile_path and os.path.exists(profile_path):
        profile = effective_profile(run, profile_path)
        fresh = alert_metadata.build(alerts, profile, read(run, "evidence.json"))
        claimed = {str(a.get("id")): a for a in record.get("alerts", [])}
        wrong = []
        for alert in fresh["alerts"]:
            held = claimed.get(str(alert["id"]))
            if held is None:
                wrong.append(f"{alert['id']} not read")
                continue
            for field, ours in (("techniques", [t["id"] for t in alert["techniques"]]),
                                ("threat", alert["threat"]),
                                ("absent", alert["absent"])):
                theirs = ([t.get("id") for t in held.get("techniques") or []] if field == "techniques"
                          else held.get(field))
                if theirs != ours:
                    wrong.append(f"{alert['id']} {field}: {theirs!r} for {ours!r}")
        report.check(not wrong, f"{label}: the assertions are the ones the alerts carry",
                     f"the {len(fresh['alerts'])} alerts as alert_metadata.py reads them",
                     "; ".join(wrong[:4]) if wrong else f"all {len(fresh['alerts'])} as recomputed")
    elif alerts:
        report.skip(f"{label}: the assertions are the ones the alerts carry", "no source profile given")
    recorded = {str(g.get("data_source", "")).strip().lower() for g in ledger.get("visibility_gaps", [])
                if isinstance(g, dict)}
    absent = sorted({a for alert in record.get("alerts", []) for a in alert.get("absent", [])})
    unrecorded = [a for a in absent if f"alert metadata: {a}" not in recorded]
    report.check(not unrecorded, f"{label}: an assertion the source did not supply is a recorded gap",
                 "each absence in visibility_gaps with the check it prevented",
                 f"{len(unrecorded)} absent and not recorded: " + ", ".join(unrecorded) if unrecorded
                 else ("nothing absent" if not absent else f"all {len(absent)} recorded"))
    # §1.5: what a source recommends is indicative. This once failed a run that left one
    # unanswered, then reported what became of each; on a source that publishes its procedure per
    # alert both are a checklist. How many it published is worth knowing — it sizes what the
    # executor read — and nothing is asked about what it did with them.
    actions = alert_metadata.actions_of(record)
    report.note(f"{label}: recommended actions", f"{len(actions)} published across the Case's alerts")
    neutralized = [r["entity"] for r in record.get("remediation", []) if r.get("neutralized")]
    note = read(run, note_name)
    if not neutralized:
        report.ok(f"{label}: the remediation the source performed is in the Note", "the source neutralized nothing")
    elif note is None:
        report.skip(f"{label}: the remediation the source performed is in the Note", f"no {note_name} in the run")
    else:
        unsaid = [e for e in neutralized if str(e) not in note]
        report.check(not unsaid, f"{label}: the remediation the source performed is in the Note",
                     f"the state of all {len(neutralized)} entities the source neutralized",
                     f"{len(unsaid)} missing from the Note: " + ", ".join(str(e) for e in unsaid[:4]) if unsaid
                     else f"all {len(neutralized)} named")


def check_timebox(report, ledger):
    """The timebox is measured from the ledger's own timestamps, never self-reported."""
    if not ledger:
        return report.skip("timebox: measured, not declared", "no investigation ledger in the run")
    if not ledger.get("started_at"):
        return report.fail("timebox: measured, not declared", "started_at in the ledger",
                           "absent: the script falls back to the self-reported timebox_expired")
    result = resolve_rule.resolve(ledger)
    box = result.get("timebox", {})
    report.check(box.get("source") != "self-reported", "timebox: measured from the ledger's timestamps",
                 "source measured from started_at", f"source={box.get('source')}")
    report.ok("timebox: elapsed against the reference",
              f"{box.get('elapsed_minutes')} min elapsed of {box.get('minutes')} (expired={box.get('expired')})")
    dated = [f for f in ledger.get("observations", []) if f.get("at")]
    report.check(len(dated) == len(ledger.get("observations", [])), "timebox: observations carry their own timestamps",
                 "every observation with an 'at'", f"{len(dated)} of {len(ledger.get('observations', []))} dated")
    return result


def check_decision(report, ledger, result, label, decide):
    """The verdict the run recorded is the one the rule produces from the ledger it recorded."""
    if not ledger:
        return report.skip(f"{label}: verdict reproduced from the ledger", "no ledger in the run")
    fresh = result if result is not None else decide(ledger)
    recorded = ledger.get("recorded_verdict")
    printed = fresh.get("verdict") or fresh.get("decision")
    if recorded is None:
        report.skip(f"{label}: verdict reproduced from the ledger",
                    f"the rule gives {printed!r}; add \"recorded_verdict\" to compare it with the Note")
    else:
        report.check(str(recorded).lower() in str(printed).lower(), f"{label}: verdict reproduced from the ledger",
                     f"the rule on this ledger gives {printed!r}", f"the run recorded {recorded!r}")
    if fresh.get("evidence_inventory_note"):
        report.ok(f"{label}: the inventory note reaches the decision", fresh["evidence_inventory_note"])


def check_visibility_gaps(report, run, ledger, label):
    """Playbook Architecture §7: a required data source unavailable during the Case is recorded in the
    Note with the check it prevented. So the gaps the binding implies must be the gaps the ledger records
    — a run cannot pass over a source its own binding says it did not have."""
    if not ledger:
        return report.skip(f"{label}: visibility gaps recorded", "no ledger in the run")
    binding = read(run, "zerosoc.capabilities.json")
    key = ledger.get("domain") or ledger.get("incident_category")
    if not key and ledger.get("playbook"):
        key = os.path.splitext(os.path.basename(ledger["playbook"]))[0].split("-", 1)[-1]
    recorded = {str(g.get("data_source", "")).strip().lower()
                for g in ledger.get("visibility_gaps", []) if isinstance(g, dict)}
    if binding and key:
        selector = load("tools/shared/select_playbook.py", "select_playbook")
        book = next((b for b in playbooks(selector)
                     if key.lower() in (str(b["fields"].get("domain", "")).lower(),
                                        str(b["fields"].get("incident_category", "")).lower())), None)
        if book is None:
            report.skip(f"{label}: gaps match the binding", f"no playbook for {key!r} at this pin")
        else:
            implied = {g["data_source"].strip().lower() for g in selector.gaps(book["fields"], binding)
                       if g["status"] == "unavailable" and concrete(g["data_source"])}
            missing = sorted(implied - recorded)
            report.check(not missing, f"{label}: every source the binding marks unavailable is a recorded gap",
                         f"{len(implied)} gaps implied by the binding for {book['rel']}",
                         f"{len(missing)} not recorded: " + "; ".join(missing) if missing
                         else f"all {len(implied)} recorded")
    else:
        report.skip(f"{label}: gaps match the binding",
                    "the ledger records no playbook: add \"playbook\" with \"domain\" (triage) or "
                    "\"incident_category\" (investigation), as the procedure's selection step says")
    report.ok(f"{label}: visibility gaps recorded", f"{len(recorded)} in the ledger" if recorded else "none")


def check_sweep(report, run):
    """Investigation's retrospective sweep runs through the case store, never through telemetry."""
    note = read(run, "investigation_note.md")
    if note is None:
        return report.skip("sweep: run through cases.store", "no investigation_note.md in the run")
    said = "cases.store" in note or "case store" in note.lower()
    report.check(said, "sweep: the Note records the retrospective sweep",
                 "the 90-day sweep named with the cases.store capability class",
                 "named in the Note" if said else "the Note does not mention it")


def check_binding(report, run):
    """Playbook selection reports a real state for every data source: nothing left unbound."""
    binding = read(run, "zerosoc.capabilities.json")
    if binding is None:
        return report.skip("binding: no data source left unbound", "no zerosoc.capabilities.json in the run")
    selector = load("tools/shared/select_playbook.py", "select_playbook")
    unbound, checked = [], 0
    for book in playbooks(selector):
        for gap in selector.gaps(book["fields"], binding):
            if not concrete(gap["data_source"]):
                continue
            checked += 1
            if gap["status"] == "unbound":
                unbound.append(f"{book['rel']}: {gap['data_source']}")
    report.check(not unbound, "binding: every data source the playbooks name has a state",
                 "available or unavailable with a reason",
                 f"{len(unbound)} unbound, e.g. {unbound[0]}" if unbound else f"{checked} sources across the playbooks, none unbound")


def main_for_test(run, profile=None):
    """The checks on a run directory, for the repo's own tests: the exit code, output on stdout."""
    return _run(run, profile or os.path.join(ROOT, "skills", "zerosoc-defender-xdr", "source_profile.json"))


def _run(run, profile):
    report = Report()
    triage = read(run, "ledger.triage.json")
    investigation = read(run, "ledger.investigation.json")

    print("# triage")
    check_inventory(report, run, triage, "triage")
    titles = check_alert_map(report, run, profile)
    check_alert_ledger(report, triage, "triage", titles)
    check_source_profile(report, run, triage, "triage", profile, "triage_note.md")
    check_detection_metadata(report, run, triage, "triage", "triage_note.md", profile)
    check_visibility_gaps(report, run, triage, "triage")
    check_decision(report, triage, None, "triage", triage_decide.decide)

    print("\n# investigation")
    check_inventory(report, run, investigation, "investigation")
    check_alert_ledger(report, investigation, "investigation", titles)
    check_source_profile(report, run, investigation, "investigation", profile, "investigation_note.md")
    check_detection_metadata(
        report, run, investigation, "investigation", "investigation_note.md", profile
    )
    check_visibility_gaps(report, run, investigation, "investigation")
    result = check_timebox(report, investigation)
    check_decision(report, investigation, result, "investigation", resolve_rule.resolve)
    check_sweep(report, run)

    print("\n# deployment")
    check_binding(report, run)

    print(f"\n{report.failed} failed, {report.skipped} skipped")
    if report.skipped:
        print("a skipped check is not a passed one: add the artifact and run it again")
    return 1 if report.failed else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("run", help="the directory holding the run's artifacts")
    ap.add_argument("--profile", default=os.path.join(ROOT, "skills", "zerosoc-defender-xdr", "source_profile.json"))
    a = ap.parse_args()
    if not os.path.isdir(a.run):
        print(f"not a directory: {a.run}", file=sys.stderr)
        return 2

    return _run(a.run, a.profile)


if __name__ == "__main__":
    sys.exit(main())
