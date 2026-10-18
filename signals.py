"""
Intelligence Desk — pattern signals computed over the incident store at export time.

Three signals, each grounded in a measured effect (see project note "hoax_threat_geography_test_oct2026"):

  repeat    A county that took a hoax threat has ~2x the chance of another within 7 days
            (23 of 179 events vs 11 expected, p<0.0005, Aug–Oct 2026). Usually a LOCAL serial
            offender (a student, someone with a local tie); these series get solved.
  wave      Same-day hoax threats in 3+ counties of one state. Same-day same-state pairs run
            ~1.8x chance (p≈0.006). The signature of a REMOTE caller working a list.
  stacked   One call claiming BOTH a bomb and an active shooter: forces evacuation and lockdown
            protocols at once. Seen at Florence WI, Bangor ME, North Kansas City MO (Oct 2026).
            A plausible remote-caller fingerprint; still a small sample, so it is surfaced, not scored.

County comes from the geocoder (see engine.geocode) and is stored on the incident row.
Only "hoax-type" incidents feed the signals: Bomb Threat and Swatting / Active-Shooter Hoax.
Suspicious-package mailings are a different phenomenon and are excluded.
"""
import re, datetime, collections

VERSION = "1"
HOAX_TYPES = ("Bomb Threat", "Swatting / Active-Shooter Hoax")
REPEAT_DAYS = 7
WAVE_MIN_COUNTIES = 3
LOOKBACK_DAYS = 45          # signals are only computed for recent rows; older rows carry none

_BOMB = re.compile(r"\bbomb|explosive", re.I)
_SHOOT = re.compile(r"active[- ]shooter|shooter|shooting|gunman|shots fired", re.I)


def _d(s):
    try:
        return datetime.date.fromisoformat((s or "")[:10])
    except ValueError:
        return None


def _event_key(r):
    """Collapse records of the same event (two outlets, two names) to one key."""
    name = re.sub(r"[^a-z0-9]", "", (r["facility_name"] or "").lower())[:14]
    return (r["country"], r["county"] or "", r["date"][:10], name)


def compute(con, today=None):
    """Return ({incident_id: flags}, summary). flags keys: repeat, wave, stacked."""
    today = today or datetime.date.today()
    since = (today - datetime.timedelta(days=LOOKBACK_DAYS)).isoformat()
    rows = con.execute("""SELECT id, country, region, county, facility_name, town, date, trigger_type,
                                 evidence_quote, cluster_hint
                          FROM incidents WHERE date >= ? ORDER BY date""", (since,)).fetchall()
    cols = ["id", "country", "region", "county", "facility_name", "town", "date", "trigger_type",
            "evidence_quote", "cluster_hint"]
    recs = [dict(zip(cols, r)) for r in rows if _d(r[6])]
    hoax = [r for r in recs if r["trigger_type"] in HOAX_TYPES]

    flags = collections.defaultdict(dict)

    # ---- stacked: bomb + shooter in one record's text, or both types at one facility on one day
    by_fac_day = collections.defaultdict(set)
    for r in hoax:
        by_fac_day[(r["country"], r["date"][:10], re.sub(r"[^a-z0-9]", "", (r["facility_name"] or "").lower())[:14])].add(r["trigger_type"])
    for r in hoax:
        text = " ".join(x or "" for x in (r["evidence_quote"], r["cluster_hint"], r["facility_name"]))
        k = (r["country"], r["date"][:10], re.sub(r"[^a-z0-9]", "", (r["facility_name"] or "").lower())[:14])
        both_text = bool(_BOMB.search(text) and _SHOOT.search(text))
        both_types = len(by_fac_day[k]) >= 2
        if both_text or both_types:
            flags[r["id"]]["stacked"] = True

    # ---- repeat: prior hoax events in the same county within REPEAT_DAYS (distinct events only)
    by_county = collections.defaultdict(list)
    for r in hoax:
        if r["county"]:
            by_county[(r["country"], r["county"])].append(r)
    for key, L in by_county.items():
        events = {}
        for r in L:
            events.setdefault(_event_key(r), []).append(r)
        for ek, members in events.items():
            d0 = _d(ek[2])
            prior = sorted({e[2] for e in events if e != ek and 0 < (d0 - _d(e[2])).days <= REPEAT_DAYS})
            if prior:
                for r in members:
                    flags[r["id"]]["repeat"] = {"prior": len(prior), "first": prior[0], "window_days": REPEAT_DAYS}

    # ---- wave: same country+state, same day, hoax events in >= WAVE_MIN_COUNTIES distinct counties
    by_state_day = collections.defaultdict(list)
    for r in hoax:
        if r["region"]:
            by_state_day[(r["country"], r["region"], r["date"][:10])].append(r)
    waves = []
    for (country, region, day), L in by_state_day.items():
        counties = {r["county"] for r in L if r["county"]}
        if len(counties) >= WAVE_MIN_COUNTIES:
            events = {_event_key(r) for r in L}
            wave = {"date": day, "country": country, "region": region, "counties": len(counties),
                    "events": len(events), "key": "%s|%s|%s" % (day, country, region)}
            waves.append(wave)
            for r in L:
                flags[r["id"]]["wave"] = {"key": wave["key"], "counties": len(counties), "events": len(events)}

    # ---- summary for the board: recent waves, counties on a repeat run, recent stacked calls
    recent = (today - datetime.timedelta(days=14)).isoformat()
    repeat_counties = []
    for key, L in by_county.items():
        events = {}
        for r in L:
            events.setdefault(_event_key(r), r)
        dates = sorted({e[2] for e in events if e[2] >= recent})
        if len(dates) >= 2:
            any_r = next(iter(events.values()))
            repeat_counties.append({"county": key[1], "region": any_r["region"], "country": key[0],
                                    "events": len(dates), "dates": dates})
    repeat_counties.sort(key=lambda x: (-x["events"], x["dates"][-1]), reverse=False)
    stacked_recent, seen_ev = [], set()
    for r in hoax:
        if flags.get(r["id"], {}).get("stacked") and r["date"][:10] >= recent:
            ek = _event_key(r)[:3] + (re.sub(r"[^a-z0-9]", "", (r["facility_name"] or "").lower())[:8],)
            if ek in seen_ev: continue
            seen_ev.add(ek)
            stacked_recent.append({"id": r["id"], "date": r["date"][:10], "facility": r["facility_name"],
                                   "region": r["region"], "country": r["country"]})
    summary = {
        "version": VERSION,
        "computed": today.isoformat(),
        "definitions": {
            "repeat": "another hoax threat in the same county within the prior %d days (~2x base rate; usually a local serial offender)" % REPEAT_DAYS,
            "wave": "same-day hoax threats in %d+ counties of one state (remote-caller sweep)" % WAVE_MIN_COUNTIES,
            "stacked": "one call claiming both a bomb and an active shooter",
        },
        "waves": sorted([w for w in waves if w["date"] >= recent], key=lambda w: w["date"], reverse=True),
        "repeat_counties": repeat_counties[:12],
        "stacked_recent": sorted(stacked_recent, key=lambda s: s["date"], reverse=True)[:12],
    }
    return dict(flags), summary


if __name__ == "__main__":
    import sqlite3, json, sys
    con = sqlite3.connect(sys.argv[1] if len(sys.argv) > 1 else "incidents.db")
    f, s = compute(con)
    print(json.dumps(s, indent=1))
    print("flagged rows:", len(f), "| repeat:", sum('repeat' in v for v in f.values()),
          "| wave:", sum('wave' in v for v in f.values()), "| stacked:", sum('stacked' in v for v in f.values()))
