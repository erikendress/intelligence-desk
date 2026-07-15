#!/usr/bin/env python3
"""
OnScene Technologies — Intelligence Desk recognition engine (reference implementation)

Pipeline:  ingest public news  ->  classify with Claude  ->  de-duplicate & cluster in SQLite  ->  export incidents.json

Run it:
    python engine.py --mock        # no API key needed; uses fixtures.json to prove the pipeline
    python engine.py               # live run; needs the env var ANTHROPIC_API_KEY

The board reads the exported incidents.json. GitHub Actions runs this on a schedule
and commits the updated feed — no server, nobody feeding it by hand.
"""
import os, re, json, sqlite3, argparse, datetime, hashlib, urllib.parse, urllib.request

DB   = os.path.join(os.path.dirname(__file__), "incidents.db")
OUT  = os.path.join(os.path.dirname(__file__), "incidents.json")
SCHEMA = os.path.join(os.path.dirname(__file__), "schema.sql")

# Terms cast a wide net; the classifier is what actually decides what qualifies.
QUERY = '(school OR schools OR campus) (swatting OR "bomb threat" OR lockdown OR evacuated OR "shelter in place" OR "active shooter") sourcelang:eng'

SYSTEM_PROMPT = """You are an incident-recognition analyst for the OnScene Technologies Intelligence Desk,
covering school and campus safety in the US and UK. You read ONE news article and decide whether it
reports a qualifying safety event, then return JSON only.

INCLUDE an event if EITHER (a) a facility (school, college/university, and later workplace or public venue)
faced a hostile safety threat — swatting / active-shooter hoax, bomb threat, weapon or intruder, or a
credible threat of violence; OR (b) a facility took a protective action for a safety reason — lockdown,
lockout/secure, shelter-in-place, evacuation, invacuation, early dismissal, or closure.

EXCLUDE general trend/analysis pieces with no single datable incident at a named facility; non-safety
disruptions (weather, staffing, utilities) unless a safety protective action was taken; opinion, policy,
and historical retrospectives.

RULES: Extract only what the text supports; use null for unknowns. Never assert a hoax-or-real
determination the article does not state — use "Under investigation". If one event affected multiple named
facilities, emit one record per facility and give them the SAME cluster_hint. Quote a short verbatim
evidence span. Assign confidence 0..1 from source clarity and corroboration.

OUTPUT exactly one JSON object:
  Not a qualifying event:  {"include": false, "reason": "<one line>"}
  A qualifying event:      {"include": true, "records": [ { ...fields... } ]}
Each record's fields:
  facility_name, facility_type ("K-12"|"Higher Ed"|"Workplace"|"Venue"),
  town, region (US state or UK county/nation), country ("US"|"UK"),
  date ("YYYY-MM-DD"), trigger_type, protective_action, outcome_status,
  injuries (int|null), schools_affected (int|null),
  cluster_hint (string), confidence (0..1), evidence_quote (string)."""

# ----------------------------------------------------------------------------- ingest
NEWS_QUERY = ('school (swatting OR "bomb threat" OR lockdown OR evacuated '
              'OR "shelter in place" OR "active shooter")')

def _fetch_google_news(gl, ceid, days, maxrecords):
    import time as _t, xml.etree.ElementTree as ET
    q = NEWS_QUERY + " when:%dd" % days
    url = "https://news.google.com/rss/search?" + urllib.parse.urlencode(
        {"q": q, "hl": "en-US", "gl": gl, "ceid": ceid})
    headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko)"}
    raw = None
    for attempt in range(4):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as r:
                raw = r.read()
            break
        except Exception as e:
            if attempt == 3:
                print("ingest: %s feed failed after retries: %s" % (ceid, e))
                return []
            _t.sleep(5 * (attempt + 1))
    out = []
    try:
        root = ET.fromstring(raw)
    except Exception as e:
        print("ingest: could not parse %s feed: %s" % (ceid, e))
        return []
    for item in root.iter("item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        pub = (item.findtext("pubDate") or "").strip()
        src = item.find("source")
        domain = (src.text or "").strip() if src is not None else ""
        if title:
            out.append({"title": title, "url": link, "domain": domain, "published": pub, "text": title})
        if len(out) >= maxrecords:
            break
    return out

def ingest_live(days=3, maxrecords=60):
    seen, merged = set(), []
    for gl, ceid in [("US", "US:en"), ("GB", "GB:en")]:
        for a in _fetch_google_news(gl, ceid, days, maxrecords):
            if a["url"] and a["url"] not in seen:
                seen.add(a["url"]); merged.append(a)
    print("ingest: pulled %d articles from Google News (US+UK)" % len(merged))
    return merged

def ingest_mock():
    return json.load(open(os.path.join(os.path.dirname(__file__), "fixtures.json")))

# ----------------------------------------------------------------------------- classify
def classify_live(article):
    import anthropic
    client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY
    user = (f"Title: {article.get('title')}\nSource: {article.get('domain')}\n"
            f"Date: {article.get('published')}\nURL: {article.get('url')}\n\n{article.get('text','')}")
    msg = client.messages.create(
        model="claude-haiku-4-5", max_tokens=1200,
        system=SYSTEM_PROMPT, messages=[{"role": "user", "content": user}])
    return _parse_json(msg.content[0].text)

def classify_mock(article):
    return article.get("label")  # fixtures carry the expected classifier output

def _parse_json(txt):
    m = re.search(r"\{.*\}", txt, re.S)
    if not m:
        return {"include": False, "reason": "unparseable model output"}
    try:
        return json.loads(m.group(0))
    except Exception:
        return {"include": False, "reason": "invalid json from model"}

# ----------------------------------------------------------------------------- geocode (optional)
GEO_CACHE = {}
def geocode(rec):
    """Fill lat/lng from town/region via OpenStreetMap Nominatim (free, no key)."""
    if rec.get("lat") and rec.get("lng"):
        return rec["lat"], rec["lng"]
    country = "United Kingdom" if rec.get("country") == "UK" else "United States"
    q = ", ".join(x for x in [rec.get("town"), rec.get("region"), country] if x)
    if not q:
        return None, None
    if q in GEO_CACHE:
        return GEO_CACHE[q]
    import time
    try:
        url = "https://nominatim.openstreetmap.org/search?" + urllib.parse.urlencode(
            {"q": q, "format": "json", "limit": 1})
        req = urllib.request.Request(url, headers={
            "User-Agent": "OnSceneTechnologiesIntelligenceDesk/1.0 (contact: info@onscenetechnologies.com)"})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.load(r)
        time.sleep(1)
        if data:
            latlng = (round(float(data[0]["lat"]), 4), round(float(data[0]["lon"]), 4))
            GEO_CACHE[q] = latlng
            return latlng
    except Exception:
        pass
    GEO_CACHE[q] = (None, None)
    return None, None

# ----------------------------------------------------------------------------- store
def init_db():
    con = sqlite3.connect(DB)
    con.executescript(open(SCHEMA).read())
    con.execute("CREATE TABLE IF NOT EXISTS seen_articles (url TEXT PRIMARY KEY, seen_at TEXT)")
    return con

def slug(s):
    return re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-")[:60]

def upsert(con, rec):
    now = datetime.datetime.utcnow().isoformat()
    key = hashlib.sha1(f"{rec.get('facility_name')}|{rec.get('date')}|{rec.get('trigger_type')}".lower().encode()).hexdigest()
    lat, lng = geocode(rec)
    cur = con.execute("SELECT outcome_status FROM incidents WHERE dedup_key=?", (key,))
    existing = cur.fetchone()
    if existing is None:
        con.execute("""INSERT INTO incidents
          (dedup_key, facility_name, facility_type, town, region, country, lat, lng, date,
           trigger_type, protective_action, outcome_status, injuries, schools_affected,
           cluster_hint, cluster_id, confidence, evidence_quote, source_domain, source_url,
           first_seen, last_updated)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
          (key, rec.get("facility_name"), rec.get("facility_type"), rec.get("town"), rec.get("region"),
           rec.get("country"), lat, lng, rec.get("date"), rec.get("trigger_type"),
           rec.get("protective_action"), rec.get("outcome_status"), rec.get("injuries"),
           rec.get("schools_affected"), rec.get("cluster_hint"), slug(rec.get("cluster_hint")),
           rec.get("confidence"), rec.get("evidence_quote"), rec.get("_domain"), rec.get("_url"),
           now, now))
        return "new"
    # records mature: promote an "Under investigation" record when a later story confirms it
    if existing[0] == "Under investigation" and rec.get("outcome_status") not in (None, "Under investigation"):
        con.execute("UPDATE incidents SET outcome_status=?, last_updated=? WHERE dedup_key=?",
                    (rec.get("outcome_status"), now, key))
        return "updated"
    return "dup"

def assign_clusters(con):
    # A cluster is any cluster_hint shared by 2+ facility records.
    con.execute("UPDATE incidents SET cluster_id=NULL")
    for hint, n in con.execute("SELECT cluster_hint, COUNT(*) FROM incidents WHERE cluster_hint IS NOT NULL GROUP BY cluster_hint"):
        if n >= 2:
            con.execute("UPDATE incidents SET cluster_id=? WHERE cluster_hint=?", (slug(hint), hint))

# ----------------------------------------------------------------------------- export
def export(con):
    rows = con.execute("""SELECT id, country, date, facility_name, town, region, facility_type,
        trigger_type, protective_action, outcome_status, cluster_hint, evidence_quote, lat, lng,
        source_domain, source_url FROM incidents ORDER BY date DESC""").fetchall()
    incidents = [{
        "id": r[0], "country": r[1], "date": r[2], "school": r[3], "city": r[4], "state": r[5],
        "sector": r[6], "type": r[7], "response": r[8], "outcome": r[9], "cluster": r[10] or "",
        "notes": r[11] or "", "lat": r[12], "lng": r[13], "src": r[14], "url": r[15]
    } for r in rows]
    json.dump({"generated": datetime.datetime.utcnow().isoformat() + "Z",
               "count": len(incidents), "incidents": incidents},
              open(OUT, "w"), indent=2)
    return len(incidents)

# ----------------------------------------------------------------------------- run
def run(mock=False):
    con = init_db()
    articles = ingest_mock() if mock else ingest_live()
    now = datetime.datetime.utcnow().isoformat()
    stats = {"ingested": len(articles), "skipped_seen": 0, "recognized": 0, "new": 0, "updated": 0, "rejected": 0, "errors": 0}
    for a in articles:
        url = a.get("url")
        if url and con.execute("SELECT 1 FROM seen_articles WHERE url=?", (url,)).fetchone():
            stats["skipped_seen"] += 1
            continue
        try:
            res = classify_mock(a) if mock else classify_live(a)
            if url:
                con.execute("INSERT OR IGNORE INTO seen_articles(url, seen_at) VALUES (?,?)", (url, now))
            if not res or not res.get("include"):
                stats["rejected"] += 1
                continue
            for rec in (res.get("records") or []):
                if not rec.get("facility_name") or not rec.get("date"):
                    continue  # skip incomplete records
                rec["_domain"] = a.get("domain"); rec["_url"] = a.get("url")
                outcome = upsert(con, rec)
                stats["recognized"] += 1
                if outcome in ("new", "updated"):
                    stats[outcome] += 1
        except Exception as e:
            stats["errors"] += 1
            print("skip article (%s): %s" % (a.get("url"), e))
            continue
    assign_clusters(con)
    con.commit()
    total = export(con)
    print(json.dumps({**stats, "total_in_db": total, "output": OUT}, indent=2))

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--mock", action="store_true", help="run offline against fixtures.json")
    run(mock=ap.parse_args().mock)
