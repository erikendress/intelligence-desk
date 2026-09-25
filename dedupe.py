"""
Intelligence Desk: incident de-duplication.

The old dedup_key was an exact hash of facility_name|date|trigger_type, so the same event
slipped through whenever outlets worded it differently ("Caldwell High" vs "Caldwell High
School", "Swatting" vs "Swatting / False report", or the article date instead of the event date).

This module matches on meaning instead:
  * trigger_type is folded into a small fixed set of categories
  * facility names are normalized (case, punctuation, generic words like "school" and "high")
  * a new record matches an existing one when it's the same country and category,
    no more than 1 day apart, with a matching name and nearby location

A match merges the record into the existing incident. The extra article is kept in
incident_sources, so no source is lost.

    python dedupe.py            # one-time cleanup of incidents.db, then re-export
    python dedupe.py --dry-run  # show what would merge without changing anything
"""
import re, math, datetime, difflib

VERSION = "2"
WINDOW_DAYS = 1          # same event reported on consecutive days merges; a real repeat 2+ days later stays separate
GEO_KM = 40              # "same place" radius when towns are spelled differently

# ------------------------------------------------------------------ canonical categories
TRIGGERS = ["Swatting / Active-Shooter Hoax", "Bomb Threat", "Weapon / Intruder",
            "Actual Violence", "Credible Threat", "Non-threat safety cause"]

def canon_trigger(t):
    t = (t or "").lower().strip()
    if not t or t in ("unknown", "under investigation", "threat under investigation", "other"):
        return None      # the model sometimes puts the outcome in this field; treat as "any category"
    if re.search(r"swat|hoax.*shoot|shoot.*hoax|false.*(shoot|report|emergency)|fake.*call", t):
        return "Swatting / Active-Shooter Hoax"
    if re.search(r"bomb|explos|suspicious (package|object|vehicle|device)|unattended package|\bied\b|device", t):
        return "Bomb Threat"
    if re.search(r"fire|gas|chemical|hazmat|hazard|leak|smell|weather|wildlife|structural|plume|drill|alarm|thunder", t):
        return "Non-threat safety cause"
    if re.search(r"shooting|shots fired|gunfire|gunshot|stabb|shootout|attack", t) and not re.search(r"report|threat|unfounded|false", t):
        return "Actual Violence"
    if re.search(r"weapon|armed|gun|knife|machete|intruder|firearm|hammer|stabb|shot|shoot", t):
        return "Weapon / Intruder"
    return "Credible Threat"

OUTCOME_RANK = {"under investigation": 0}
def outcome_rank(o):
    o = (o or "").lower()
    if not o or "investigat" in o or o == "unknown":
        return 0
    if "hoax" in o or "false" in o or "arrest" in o or "charge" in o:
        return 3
    return 1

# ------------------------------------------------------------------ name normalization
LEVELS = {"high": "high", "hs": "high", "senior": "high", "secondary": "high", "middle": "middle",
          "junior": "middle", "intermediate": "middle", "elementary": "elem", "primary": "elem"}
GENERIC = set("""the a an of at in and school schools academy campus public private government govt district unified usd isd building buildings
facility center centre complex main unnamed unspecified multiple several various local area
specific some other nearby near downtown hospital medical health healthcare""".split())

# names made only of these words ("City Hall", "Walmart", "courthouse") are too common to match on name alone
COMMON = set("""city town hall court courts courthouse county state federal district police station post
office library airport terminal mall church mosque temple synagogue bank store hotel business company
manufacturing walmart target consulate embassy annex""".split())

def _tokens(s):
    s = (s or "").lower().replace("&", " and ")
    s = re.sub(r"\(.*?\)", " ", s)             # drop parentheticals: "(multiple)", "(6 schools)"
    s = re.sub(r"[^a-z0-9 ]+", " ", s)
    return [w for w in s.split() if w]

def norm_name(name, town=None):
    """Meaningful words only; school level words are kept apart (see _level) and town words dropped."""
    toks = [w for w in _tokens(name) if w not in GENERIC and w not in LEVELS and not w.isdigit()]
    town_toks = set(_tokens(town))
    stripped = [w for w in toks if w not in town_toks]
    return " ".join(stripped or toks)

def _level(name):
    return {LEVELS[w] for w in _tokens(name) if w in LEVELS}

def is_generic(name, town=None):
    """Placeholder facilities the model invents: 'School 2, Delhi', 'Schools in Punjab', 'Local high school'."""
    town_toks = set(_tokens(town)) | {"schools", "school"}
    rest = [w for w in _tokens(name) if w not in GENERIC and w not in LEVELS and not w.isdigit() and w not in town_toks]
    return len(rest) == 0

def _acronym(name):
    """'Northeast Georgia Medical Center' -> {'ngmc', 'ngm'} so it matches 'NGMC Gainesville'."""
    toks = [w for w in _tokens(name) if w not in ("the", "of", "and", "at")]
    if len(toks) < 3:
        return set()
    full = "".join(w[0] for w in toks)
    return {full, "".join(w[0] for w in toks if w not in GENERIC)} - {""}

def norm_town(t):
    return " ".join(_tokens(t))

def _km(a, b):
    if None in (a[0], a[1], b[0], b[1]):
        return None
    la1, lo1, la2, lo2 = map(math.radians, (a[0], a[1], b[0], b[1]))
    h = math.sin((la2 - la1) / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
    return 6371 * 2 * math.asin(math.sqrt(h))

def _days(d1, d2):
    try:
        return abs((datetime.date.fromisoformat(d1) - datetime.date.fromisoformat(d2)).days)
    except Exception:
        return 99

# ------------------------------------------------------------------ the match rule
def same_incident(a, b):
    """a, b: dicts with facility_name, town, region, country, date, trigger_type, facility_type, lat, lng."""
    if (a.get("country") or "").lower() != (b.get("country") or "").lower():
        return False
    ca, cb = canon_trigger(a.get("trigger_type")), canon_trigger(b.get("trigger_type"))
    # "Credible Threat" is the catch-all for vaguely worded threats, so it can pair with a more specific category
    if ca and cb and ca != cb and "Credible Threat" not in (ca, cb):
        return False
    la, lb = _level(a.get("facility_name")), _level(b.get("facility_name"))
    if la and lb and not (la & lb):
        return False    # "Lake City High" and "Lake City Middle" are different buildings
    if _days(a.get("date"), b.get("date")) > WINDOW_DAYS:
        return False

    ta, tb = norm_town(a.get("town")), norm_town(b.get("town"))
    km = _km((a.get("lat"), a.get("lng")), (b.get("lat"), b.get("lng")))
    same_place = (ta and ta == tb) or (km is not None and km <= GEO_KM)

    ga, gb = is_generic(a.get("facility_name"), a.get("town")), is_generic(b.get("facility_name"), b.get("town"))
    if ga or gb:
        # a placeholder ("Gainesville hospital", "School 2, Delhi") merges only within the same town and sector
        return bool(ta) and ta == tb and a.get("facility_type") == b.get("facility_type")

    na, nb = norm_name(a.get("facility_name"), a.get("town")), norm_name(b.get("facility_name"), b.get("town"))
    if not na or not nb:
        return False
    sa, sb = set(na.split()), set(nb.split())
    ratio = difflib.SequenceMatcher(None, na, nb).ratio()
    shared = (sa & sb) - COMMON
    overlap = len(sa & sb) / min(len(sa), len(sb))
    name_match = (na == nb or ratio >= 0.85 or sa <= sb or sb <= sa
                  or (len(shared) >= 2 and overlap >= 0.66)
                  or _acronym(a.get("facility_name")) & sb or _acronym(b.get("facility_name")) & sa)
    if not name_match:
        return False
    if same_place:
        return True
    ra, rb = norm_town(a.get("region")), norm_town(b.get("region"))
    one_town_missing = not ta or not tb
    # a distinctive name ("lake city", "monument health") can match across a mis-tagged or missing town;
    # a common one ("city hall", "walmart") only when the other record has no town and the region agrees
    distinctive = min(len(sa), len(sb)) >= 2 and not (sa <= COMMON or sb <= COMMON)
    if distinctive:
        return one_town_missing or km is None or km <= 300
    if sa <= COMMON or sb <= COMMON:
        return one_town_missing and bool(ra) and ra == rb      # "City Hall": need the region to agree
    return one_town_missing and (not ra or not rb or ra == rb)


# ------------------------------------------------------------------ DB helpers
def ensure_tables(con):
    con.execute("""CREATE TABLE IF NOT EXISTS incident_sources (
        incident_id INTEGER, url TEXT, domain TEXT, added TEXT,
        PRIMARY KEY (incident_id, url))""")

COLS = ["id", "facility_name", "facility_type", "town", "region", "country", "lat", "lng", "date",
        "trigger_type", "protective_action", "outcome_status", "source_url", "source_domain"]

def find_match(con, rec):
    """Return the id of an existing incident this record duplicates, or None."""
    d = rec.get("date")
    try:
        lo = (datetime.date.fromisoformat(d) - datetime.timedelta(days=WINDOW_DAYS)).isoformat()
        hi = (datetime.date.fromisoformat(d) + datetime.timedelta(days=WINDOW_DAYS)).isoformat()
    except Exception:
        return None
    rows = con.execute("SELECT %s FROM incidents WHERE date BETWEEN ? AND ? AND lower(country)=lower(?)"
                       % ",".join(COLS), (lo, hi, rec.get("country") or "")).fetchall()
    for r in rows:
        if same_incident(rec, dict(zip(COLS, r))):
            return r[0]
    return None

def merge_into(con, keep_id, rec, now):
    """Fold a duplicate record into an existing incident: fill blanks, keep the earliest date and
    the most mature outcome, and attach the article as an extra source."""
    cur = dict(zip(COLS, con.execute("SELECT %s FROM incidents WHERE id=?" % ",".join(COLS), (keep_id,)).fetchone()))
    upd = {}
    for f in ("town", "region", "protective_action", "lat", "lng", "facility_type"):
        if not cur.get(f) and rec.get(f):
            upd[f] = rec[f]
    if not canon_trigger(cur.get("trigger_type")) and canon_trigger(rec.get("trigger_type")):
        upd["trigger_type"] = canon_trigger(rec.get("trigger_type"))
    if rec.get("date") and cur.get("date") and rec["date"] < cur["date"]:
        upd["date"] = rec["date"]
    if outcome_rank(rec.get("outcome_status")) > outcome_rank(cur.get("outcome_status")):
        upd["outcome_status"] = rec["outcome_status"]
    # prefer the more specific facility name ("Caldwell High School" over "Caldwell High")
    if len(norm_name(rec.get("facility_name"))) > len(norm_name(cur.get("facility_name"))) \
            and not is_generic(rec.get("facility_name"), rec.get("town")):
        upd["facility_name"] = rec["facility_name"]
    if upd:
        upd["last_updated"] = now
        con.execute("UPDATE incidents SET %s WHERE id=?" % ",".join("%s=?" % k for k in upd),
                    (*upd.values(), keep_id))
    url = rec.get("_url") or rec.get("source_url")
    if url:
        con.execute("INSERT OR IGNORE INTO incident_sources(incident_id,url,domain,added) VALUES (?,?,?,?)",
                    (keep_id, url, rec.get("_domain") or rec.get("source_domain"), now))
    return "updated" if "outcome_status" in upd else "dup"


# ------------------------------------------------------------------ one-time cleanup
def cleanup(con, dry_run=False, verbose=True):
    ensure_tables(con)
    now = datetime.datetime.utcnow().isoformat()
    # every existing row's own URL becomes its first source
    con.execute("""INSERT OR IGNORE INTO incident_sources(incident_id,url,domain,added)
                   SELECT id, source_url, source_domain, first_seen FROM incidents WHERE source_url IS NOT NULL""")
    rows = [dict(zip(COLS, r)) for r in con.execute(
        "SELECT %s FROM incidents ORDER BY date, id" % ",".join(COLS)).fetchall()]
    kept, merged = [], []
    for r in rows:
        match = next((k for k in reversed(kept) if same_incident(r, k)), None)
        if match:
            merged.append((r, match))
            if not dry_run:
                merge_into(con, match["id"], r, now)
                con.execute("UPDATE OR IGNORE incident_sources SET incident_id=? WHERE incident_id=?", (match["id"], r["id"]))
                con.execute("DELETE FROM incident_sources WHERE incident_id=?", (r["id"],))
                con.execute("DELETE FROM incidents WHERE id=?", (r["id"],))
        else:
            kept.append(r)
    if not dry_run:
        # store the canonical category so the board's filters and counts are consistent
        for rid, t in con.execute("SELECT id, trigger_type FROM incidents").fetchall():
            con.execute("UPDATE incidents SET trigger_type=? WHERE id=?", (canon_trigger(t) or "Under investigation", rid))
        con.commit()
    if verbose:
        print("dedupe: %d rows -> %d incidents (%d duplicates %s)"
              % (len(rows), len(kept), len(merged), "found" if dry_run else "merged"))
    return merged


if __name__ == "__main__":
    import argparse, sqlite3, os
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--db", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "incidents.db"))
    args = ap.parse_args()
    con = sqlite3.connect(args.db)
    m = cleanup(con, dry_run=args.dry_run)
    while not args.dry_run and cleanup(con):   # re-run so chains (A~B, B~C) fully collapse
        pass
    if args.dry_run:
        for dup, keep in m:
            print("  %s | %-40s  ->  %s" % (dup["date"], (dup["facility_name"] or "")[:40], keep["facility_name"]))
    else:
        import engine
        engine.export(con)
        print("re-exported incidents.json")
