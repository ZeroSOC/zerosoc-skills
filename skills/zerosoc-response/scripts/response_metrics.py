#!/usr/bin/env python3
"""The speed metrics of a confirmed Incident, from T0 (Operational Metrics §4). Standard library only.

  response_metrics.py incident.json [--json]

incident.json:
  {"verdict_id": 2, "t0": TIME, "detected_at": TIME, "entry_path": "detection" | "hunt" | "out-of-band",
   "containment": [{"requested": TIME, "decided": TIME, "applied": TIME}, ...],
   "recovered_at": TIME}

Times are ISO 8601 in UTC or milliseconds since the epoch; any may be missing, and a metric whose stop is
missing is not computed. T0 is the Case's start_time on a confirmed Incident: the metrics are computed for
a verdict of True Positive and for no other (exit 1 otherwise).

- MTTD: T0 to the originating Alert raised (G1). Its population is said, never blended: an Incident
  whose Alert came from detection content, or one discovered by threat hunting or out-of-band intake.
- MTTC: T0 to the first containment action applied and confirmed (G4), less the HITL dwell of that
  action (from proposed to decided): waiting for an approver measures the approval loop, not the
  containment. The dwell is given beside it.
- MTTR: T0 to recovery complete, services restored and containment lifted.

Each is one Incident's value; medians and p95 per severity band are taken over many.
"""
import argparse, json, sys
from datetime import datetime, timezone


def millis(value):
    if value is None:
        return None
    if isinstance(value, int) or (isinstance(value, str) and value.isdigit()):
        return int(value)
    moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return int(moment.timestamp() * 1000)


def metrics(incident):
    if incident.get("verdict_id") != 2:
        return {"error": "not a confirmed Incident: start_time is not T0, and no speed metric is computed"}
    t0 = millis(incident.get("t0"))
    if t0 is None:
        return {"error": "no T0: the confirmed Incident carries no start_time"}
    detected = millis(incident.get("detected_at"))
    applied = [
        {"requested": millis(c.get("requested")), "decided": millis(c.get("decided")), "applied": millis(c.get("applied"))}
        for c in incident.get("containment") or []
    ]
    applied = [c for c in applied if c["applied"] is not None]
    first = min(applied, key=lambda c: c["applied"]) if applied else None
    dwell = None
    if first is not None and first["requested"] is not None and first["decided"] is not None:
        dwell = max(0, first["decided"] - first["requested"])
    recovered = millis(incident.get("recovered_at"))
    entry = incident.get("entry_path") or "detection"
    return {
        "t0": t0,
        "mttd_ms": detected - t0 if detected is not None else None,
        "mttd_population": "detection content" if entry == "detection" else "threat hunting or out-of-band intake",
        "contained_at": first["applied"] if first else None,
        "hitl_dwell_ms": dwell,
        "mttc_ms": first["applied"] - t0 - (dwell or 0) if first else None,
        "recovered_at": recovered,
        "mttr_ms": recovered - t0 if recovered is not None else None,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("incident")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    with open(a.incident, encoding="utf-8") as f:
        r = metrics(json.load(f))
    if a.json:
        print(json.dumps(r, indent=2))
    elif "error" in r:
        print(r["error"])
    else:
        for name in ("mttd_ms", "mttc_ms", "hitl_dwell_ms", "mttr_ms"):
            value = r[name]
            print(f"{name[:-3].upper()}: {'not yet' if value is None else f'{value / 60000:.0f} min'}")
        print(f"MTTD population: {r['mttd_population']}")
    sys.exit(1 if "error" in r else 0)


if __name__ == "__main__":
    main()
