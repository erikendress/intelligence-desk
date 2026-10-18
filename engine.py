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
import os, re, sys, json, time, random, sqlite3, argparse, datetime, hashlib, urllib.parse, urllib.request
import dedupe, regions, signals

DB   = os.path.join(os.path.dirname(__file__), "incidents.db")
OUT  = os.path.join(os.path.dirname(__file__), "incidents.json")
SCHEMA = os.path.join(os.path.dirname(__file__), "schema.sql")

# Bump this whenever you widen scope (countries / place types). The next run then does a
# one-time clean rebuild so the feed reflects the new scope, and reverts to normal after.
BACKFILL_VERSION = "4-threatled"

# Terms cast a wide net; the classifier is what actually decides what qualifies.
QUERY = '(school OR schools OR campus) (swatting OR "bomb threat" OR lockdown OR evacuated OR "shelter in place" OR "active shooter") sourcelang:eng'

SYSTEM_PROMPT = """You are an incident-recognition analyst for the OnScene Technologies Intelligence Desk.
You cover physical-safety incidents at public-facing places in the United States, Canada and the United Kingdom. You read ONE news article and decide
whether it reports a qualifying safety event, then return JSON only.

QUALIFYING PLACES (anywhere people gather in the US, Canada or UK): schools, colleges/universities, workplaces/offices, hospitals
and other healthcare sites, houses of worship, shops/malls/retail, stadiums/arenas/event venues,
airports/train and transit stations, government buildings/courthouses, hotels, libraries, and the like.

INCLUDE an event if EITHER (a) such a place faced a hostile safety threat — swatting / active-shooter hoax,
bomb threat, weapon or intruder, or a credible threat of violence; OR (b) such a place took a protective
action for a safety reason — lockdown, lockout/secure, shelter-in-place, evacuation, invacuation, early
dismissal, or closure.

EXCLUDE: general trend/analysis pieces with no single datable incident at a named place; non-safety
disruptions (weather, staffing, utilities, power) unless a safety protective action was taken; opinion,
policy, and historical retrospectives; ordinary crime not tied to a gathering place taking a protective
action; and events that are part of an armed conflict, war zone, or military operation (this is a civilian
facility-safety desk, not a war tracker).

GEOGRAPHY: United States, Canada and the United Kingdom ONLY. Set "country" to exactly one of "United States",
"Canada" or "United Kingdom" (England, Scotland, Wales and Northern Ireland are "United Kingdom"). The Republic of
Ireland (Dublin, Cork, Cavan, Donegal, Monaghan, Galway, Limerick, etc.) is NOT the United Kingdom and is out of
scope. If the incident happened anywhere else, or you cannot tell the country from the text, return {"include": false}.

RULES: Extract only what the text supports; use null for unknowns. Never assert a hoax-or-real determination
the article does not state — use "Under investigation". Quote a short verbatim evidence span. Assign confidence
0..1 from source clarity and corroboration.

CONSISTENCY (the same event is reported by many outlets — your records must come out identical each time):
- facility_name: the facility's full official name as the article gives it ("Caldwell High School", not
  "Caldwell High"; "Northeast Georgia Medical Center", not "NGMC"). No town or parenthetical notes in the name.
- If one event affected several NAMED places, emit one record per named place with the SAME cluster_hint.
  If the places are NOT named ("three Ludhiana schools"), emit ONE record named "Schools in <town>" and put the
  number in schools_affected. Never invent placeholders like "School 1" / "School 2".
- date: the day the incident happened, not the publication date. "Monday's threat" in a Tuesday article = Monday.
- town: the municipality. region: the US state / Canadian province / UK nation — never a county. If the
  article does not state or clearly imply the state/province (e.g. "Florence County School District" with no
  state named), set region to null — never guess; there are Florence Counties in several states.
- county: the US county / Canadian regional municipality / UK council area ONLY if the article states it
  (e.g. "Lauderdale County"); otherwise null. Many towns share a name (Halls TN, Brentwood CA) — the county
  is what disambiguates them, so copy it whenever it appears.
- trigger_type: exactly one of "Swatting / Active-Shooter Hoax", "Bomb Threat", "Suspicious Package / Mail",
  "Weapon / Intruder", "Credible Threat", "Actual Violence", "Non-threat safety cause".
  "Bomb Threat" = a phoned, emailed, written or posted threat that a bomb exists. "Suspicious Package / Mail" =
  an unattended bag/package, or an envelope/letter with powder or an unknown substance, with no threat made.
- protective_action: exactly one of "Lockdown", "Lockout/Secure", "Shelter-in-place", "Evacuation",
  "Invacuation", "Early dismissal", "Closure", "None", or null.
- outcome_status: exactly one of "Under investigation", "Confirmed hoax", "Confirmed real",
  "Resolved – no cause found", "Arrest made".

OUTPUT exactly one JSON object:
  Not a qualifying event:  {"include": false, "reason": "<one line>"}
  A qualifying event:      {"include": true, "records": [ { ...fields... } ]}
Each record's fields:
  facility_name, facility_type ("K-12"|"Higher Ed"|"Workplace"|"Healthcare"|"Worship"|"Retail"|"Transit"|"Venue"|"Government"|"Other"),
  town, region (state / province / nation), county (string|null), country (full English country name),
  date ("YYYY-MM-DD"), trigger_type, protective_action, outcome_status,
  injuries (int|null), schools_affected (int|null),
  cluster_hint (string), confidence (0..1), evidence_quote (string)."""

# ----------------------------------------------------------------------------- scope
ALLOWED_COUNTRIES = ("United States", "Canada", "United Kingdom")
SCOPE_VERSION = "us-ca-uk-2"   # -2: Republic of Ireland rows (misfiled as UK) removed
# Republic of Ireland counties: the classifier has filed these under "United Kingdom" (Cavan, Donegal, Oct 2026).
ROI_COUNTIES = {"carlow", "cavan", "clare", "cork", "donegal", "dublin", "galway", "kerry", "kildare", "kilkenny",
    "laois", "leitrim", "limerick", "longford", "louth", "mayo", "meath", "monaghan", "offaly", "roscommon",
    "sligo", "tipperary", "waterford", "westmeath", "wexford", "wicklow"}

def is_republic_of_ireland(rec):
    if norm_country(rec.get("country")) != "United Kingdom":
        return False
    text = " ".join(str(rec.get(k) or "") for k in ("town", "region", "county", "facility_name")).lower()
    words = set(re.findall(r"[a-z]+", text))
    return bool(words & ROI_COUNTIES) and "northern ireland" not in text
_COUNTRY_ALIASES = {
    "united states": "United States", "united states of america": "United States", "usa": "United States",
    "us": "United States", "u.s.": "United States", "america": "United States",
    "canada": "Canada",
    "united kingdom": "United Kingdom", "uk": "United Kingdom", "u.k.": "United Kingdom",
    "great britain": "United Kingdom", "britain": "United Kingdom", "england": "United Kingdom",
    "scotland": "United Kingdom", "wales": "United Kingdom", "northern ireland": "United Kingdom",
}

def norm_country(c):
    return _COUNTRY_ALIASES.get((c or "").strip().lower())

def apply_scope(con):
    """One-time: normalize country names and drop incidents outside the US, Canada and the UK."""
    for rid, c in con.execute("SELECT id, country FROM incidents").fetchall():
        nc = norm_country(c)
        if nc:
            con.execute("UPDATE incidents SET country=? WHERE id=?", (nc, rid))
    q = "SELECT id FROM incidents WHERE country NOT IN (%s) OR country IS NULL" % ",".join("?" * len(ALLOWED_COUNTRIES))
    gone = [r[0] for r in con.execute(q, ALLOWED_COUNTRIES).fetchall()]
    for rid, fac, town, region in con.execute("SELECT id, facility_name, town, region FROM incidents WHERE country='United Kingdom'").fetchall():
        if is_republic_of_ireland({"country": "United Kingdom", "facility_name": fac, "town": town, "region": region}):
            gone.append(rid)
    for rid in gone:
        con.execute("DELETE FROM incident_sources WHERE incident_id=?", (rid,))
        con.execute("DELETE FROM incidents WHERE id=?", (rid,))
    print("scope: removed %d incidents outside %s" % (len(gone), ", ".join(ALLOWED_COUNTRIES)))

TYPES_VERSION = "2-suspicious-mail"
COUNTY_VERSION = "1"

def reclassify_types(con):
    """One-time: split suspicious packages / mailed powder out of "Bomb Threat" into their own type, so the
    bomb-threat count means phoned/written threats (mostly schools) and not the election-office mail wave."""
    n = 0
    rows = con.execute("SELECT id, trigger_type, evidence_quote, cluster_hint, facility_name FROM incidents WHERE trigger_type='Bomb Threat'").fetchall()
    for rid, t, ev, hint, fac in rows:
        text = " ".join(x or "" for x in (ev, hint, fac))
        if dedupe.canon_trigger(text) == "Suspicious Package / Mail" and not re.search(r"bomb threat|threat(ened|ening)? (to )?(bomb|blow)", text, re.I):
            con.execute("UPDATE incidents SET trigger_type='Suspicious Package / Mail' WHERE id=?", (rid,)); n += 1
    con.commit()
    print("types: reclassified %d suspicious-package rows out of Bomb Threat" % n)

# ----------------------------------------------------------------------------- ingest
# Lead with the THREAT terms and let the classifier identify the place. A place-led query
# ("school OR hospital OR ...") makes Google match the place words and return generic non-incident
# news; a threat-led query returns articles that are actually about safety events (~90% on-target).
# IMPORTANT: Google News silently DROPS the date operator (when:/after:) once a query carries
# roughly 11+ OR terms (~210 chars). The feed then returns a fixed, relevance-ranked "evergreen"
# set (median age ~2 years) that never changes - which is exactly how the feed froze in Oct 2026.
# Keep every group at 7 terms or fewer; measured threshold Oct 2026: 8 ok, 10 degraded, 11 broken.
NEWS_QUERIES = [
    '"bomb threat" OR swatting OR "active shooter" OR "shelter in place" OR "school lockdown" '
    'OR "campus lockdown" OR "building evacuated"',
    '"suspicious package" OR "lockdown lifted" OR "hoax threat" OR "suspicious item" OR "hoax call" '
    'OR "police cordon" OR "evacuated as a precaution"',
]
MAX_QUERY_TERMS = 8
for _q in NEWS_QUERIES:
    assert _q.count(" OR ") + 1 <= MAX_QUERY_TERMS, "query group too long - Google will drop the date filter"

# Google News editions to sweep: coverage is limited to the US, Canada and the UK.
EDITIONS = [("US", "US:en"), ("GB", "GB:en"), ("CA", "CA:en")]

UA_POOL = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]

# A tiny Cloudflare Worker that fetches news.google.com on our behalf (see osti-news-proxy).
# The direct route is tried first; the proxy is the fallback for when Google refuses the runner.
# Each proxy attempt lands on a different edge IP (they 503 about 3 times in 4). Set NEWS_PROXY_URL="" to disable.
NEWS_PROXY_URL = os.environ.get("NEWS_PROXY_URL", "https://osti-news-proxy.erikendress.workers.dev")
PROXY_ATTEMPTS = int(os.environ.get("PROXY_ATTEMPTS", "12"))
ROUTE_LOG = []   # per-fetch outcome, surfaced in incidents.json["last_run"] so runs are self-reporting

def _fetch_google_news(gl, ceid, days, maxrecords, query, qi=0, dated=True):
    import xml.etree.ElementTree as ET
    q = (query + " when:%dd" % days) if dated else query
    def google_url():
        return "https://news.google.com/rss/search?" + urllib.parse.urlencode(
            {"q": q, "hl": "en-US", "gl": gl, "ceid": ceid, "_": "%d%03d" % (int(time.time()), random.randint(0, 999))})
    # Route plan: direct first (two tries), then the Cloudflare proxy as a fallback.
    routes = ["direct", "direct"] + (["proxy"] * PROXY_ATTEMPTS if NEWS_PROXY_URL else [])
    for attempt, route in enumerate(routes, 1):
        gurl = google_url()
        url = (NEWS_PROXY_URL.rstrip("/") + "/?" + urllib.parse.urlencode({"url": gurl})) if route == "proxy" else gurl
        headers = {"User-Agent": random.choice(UA_POOL),
                   "Accept": "application/rss+xml,application/xml;q=0.9,*/*;q=0.8",
                   "Accept-Language": "en-US,en;q=0.9", "Cache-Control": "no-cache", "Pragma": "no-cache"}
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=60) as r:
                raw = r.read()
            root = ET.fromstring(raw)
            out = []
            for item in root.iter("item"):
                title = (item.findtext("title") or "").strip()
                link = (item.findtext("link") or "").strip()
                pub = (item.findtext("pubDate") or "").strip()
                srcel = item.find("source")
                domain = (srcel.text or "").strip() if srcel is not None else ""
                if title:
                    out.append({"title": title, "url": link, "domain": domain, "published": pub, "text": title})
                if len(out) >= maxrecords:
                    break
            if out:
                print("ingest: %s q%d ok via %s (attempt %d, %d items)" % (ceid, qi, route, attempt, len(out)))
                ROUTE_LOG.append({"edition": ceid, "q": qi, "route": route, "attempt": attempt, "items": len(out)})
                return out
            print("ingest: %s returned no items via %s (attempt %d)" % (ceid, route, attempt))
        except Exception as e:
            print("ingest: %s via %s attempt %d failed: %s" % (ceid, route, attempt, str(e)[:90]))
        time.sleep(0.8 + random.uniform(0, 0.8))
    print("ingest: %s q%d gave nothing on every route" % (ceid, qi))
    ROUTE_LOG.append({"edition": ceid, "q": qi, "route": "none", "attempt": len(routes), "items": 0})
    return []

def ingest_live(days=None, maxrecords=None):
    # Hourly runs use a tight window and a per-fetch cap. A one-off backfill widens both (see run()).
    # Env vars LOOKBACK_DAYS / MAX_RECORDS override the hourly defaults. Each edition is swept once
    # per query group (see NEWS_QUERIES), and the results are unioned by URL.
    if days is None:
        days = int(os.environ.get("LOOKBACK_DAYS", "3"))
    if maxrecords is None:
        maxrecords = int(os.environ.get("MAX_RECORDS", "60"))
    seen, merged, empty, fetches = set(), [], 0, 0
    for gl, ceid in EDITIONS:
        for qi, query in enumerate(NEWS_QUERIES):
            fetches += 1
            got = _fetch_google_news(gl, ceid, days, maxrecords, query, qi)
            if not got:
                empty += 1
            for a in got:
                if a["url"] and a["url"] not in seen:
                    seen.add(a["url"]); merged.append(a)
            time.sleep(random.uniform(1.5, 3.0))  # never burst-hit Google from a single IP
    print("ingest: pulled %d unique articles from %d fetches (%d returned nothing) - %dd window, %d/fetch cap"
          % (len(merged), fetches, empty, days, maxrecords))
    return merged

# One-time gap fill. The feed froze from Oct 3 to Oct 11 2026 (see NEWS_QUERIES). Each day in the
# window is swept with an explicit after:/before: pair so Google returns that day's articles rather
# than its relevance-ranked top 100 for the whole span. Runs once (flag in meta), then never again.
GAPFILL_VERSION = "oct2026-outage"
GAPFILL_WINDOW = ("2026-10-03", "2026-10-09")   # start inclusive, end exclusive (ISO dates)

def ingest_gap(start, end, maxrecords=100):
    d0 = datetime.date.fromisoformat(start); d1 = datetime.date.fromisoformat(end)
    seen, merged, day = set(), [], d0
    while day < d1:
        nxt = day + datetime.timedelta(days=1)
        for gl, ceid in EDITIONS:
            for qi, query in enumerate(NEWS_QUERIES):
                q = "%s after:%s before:%s" % (query, day.isoformat(), nxt.isoformat())
                got = _fetch_google_news(gl, ceid, 0, maxrecords, q, qi, dated=False)
                for a in got:
                    if a["url"] and a["url"] not in seen:
                        seen.add(a["url"]); merged.append(a)
                time.sleep(random.uniform(1.0, 2.0))
        day = nxt
    print("gapfill: pulled %d unique articles for %s..%s" % (len(merged), start, end))
    return merged

def ingest_mock():
    return json.load(open(os.path.join(os.path.dirname(__file__), "fixtures.json")))

# ----------------------------------------------------------------------------- classify
class FatalClassifyError(Exception):
    """The classifier cannot work at all (bad key, no credits) - retrying is pointless."""

def classify_live(article):
    import anthropic
    client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY
    user = (f"Title: {article.get('title')}\nSource: {article.get('domain')}\n"
            f"Date: {article.get('published')}\nURL: {article.get('url')}\n\n{article.get('text','')}")
    for attempt in range(3):
        try:
            msg = client.messages.create(
                model="claude-haiku-4-5", max_tokens=1200,
                system=SYSTEM_PROMPT, messages=[{"role": "user", "content": user}])
            return _parse_json(msg.content[0].text)
        except anthropic.AuthenticationError as e:
            raise FatalClassifyError("ANTHROPIC_API_KEY was rejected (expired or revoked?): %s" % e)
        except anthropic.PermissionDeniedError as e:
            raise FatalClassifyError("Anthropic permission denied (billing / credits?): %s" % e)
        except anthropic.RateLimitError:
            time.sleep(10 * (attempt + 1))
        except anthropic.APIStatusError as e:
            if getattr(e, "status_code", 0) in (402, 403):
                raise FatalClassifyError("Anthropic refused the request (status %s - credits/billing?): %s" % (e.status_code, e))
            time.sleep(5 * (attempt + 1))
    raise RuntimeError("classification failed after retries")

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
GEO_UA = "OnSceneTechnologiesIntelligenceDesk/1.0 (contact: info@onscenetechnologies.com)"

def _nominatim(path, params):
    url = "https://nominatim.openstreetmap.org/%s?" % path + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": GEO_UA})
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.load(r)
    time.sleep(1.05)   # Nominatim usage policy: max 1 request/second
    return data

def _county_from(address):
    """Nominatim address -> a county-level dispatch area name, or None."""
    if not address:
        return None
    for k in ("county", "state_district", "district", "municipality", "city_district"):
        v = address.get(k)
        if v:
            return v
    return None

def geocode(rec):
    """Fill lat/lng (and county) from town/county/region via OpenStreetMap Nominatim (free, no key).
    Returns (lat, lng, county). The county the classifier read from the article is used as a query hint
    so that "Halls, Lauderdale County, Tennessee" does not land on the Halls near Knoxville."""
    if rec.get("lat") and rec.get("lng"):
        return rec["lat"], rec["lng"], rec.get("county")
    if not rec.get("region") and not rec.get("county"):
        return None, None, None   # town alone is ambiguous (Florence? Jackson?) — no pin beats a wrong pin
    q = ", ".join(x for x in [rec.get("town"), rec.get("county"), rec.get("region"), rec.get("country")] if x)
    if q in GEO_CACHE:
        return GEO_CACHE[q]
    try:
        data = _nominatim("search", {"q": q, "format": "json", "limit": 1, "addressdetails": 1})
        if not data and rec.get("county"):   # the county hint can over-constrain; retry without it
            data = _nominatim("search", {"q": ", ".join(x for x in [rec.get("town"), rec.get("region"), rec.get("country")] if x),
                                         "format": "json", "limit": 1, "addressdetails": 1})
        if data:
            out = (round(float(data[0]["lat"]), 4), round(float(data[0]["lon"]), 4),
                   _county_from(data[0].get("address")) or rec.get("county"))
            GEO_CACHE[q] = out
            return out
    except Exception:
        pass
    GEO_CACHE[q] = (None, None, rec.get("county"))
    return GEO_CACHE[q]

def reverse_county(lat, lng):
    """County-level reverse geocode for rows stored before the county column existed."""
    try:
        data = _nominatim("reverse", {"lat": lat, "lon": lng, "format": "json", "zoom": 8, "addressdetails": 1})
        return _county_from(data.get("address"))
    except Exception:
        return None

def backfill_counties(con, days=60):
    """One-time: fill incidents.county for recent rows with coordinates (1 Nominatim call/second)."""
    since = (datetime.date.today() - datetime.timedelta(days=days)).isoformat()
    rows = con.execute("SELECT id, lat, lng FROM incidents WHERE county IS NULL AND lat IS NOT NULL AND lng IS NOT NULL AND date >= ?", (since,)).fetchall()
    cache, done = {}, 0
    for rid, lat, lng in rows:
        k = (round(lat, 2), round(lng, 2))
        if k not in cache:
            cache[k] = reverse_county(lat, lng)
        if cache[k]:
            con.execute("UPDATE incidents SET county=? WHERE id=?", (cache[k], rid)); done += 1
    con.commit()
    print("county backfill: %d of %d recent rows filled" % (done, len(rows)))

# ----------------------------------------------------------------------------- store
def init_db():
    con = sqlite3.connect(DB)
    con.executescript(open(SCHEMA).read())
    con.execute("CREATE TABLE IF NOT EXISTS seen_articles (url TEXT PRIMARY KEY, seen_at TEXT)")
    if "county" not in [r[1] for r in con.execute("PRAGMA table_info(incidents)").fetchall()]:
        con.execute("ALTER TABLE incidents ADD COLUMN county TEXT")
    dedupe.ensure_tables(con)
    return con

def slug(s):
    return re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-")[:60]

def upsert(con, rec):
    now = datetime.datetime.utcnow().isoformat()
    key = hashlib.sha1(f"{rec.get('facility_name')}|{rec.get('date')}|{rec.get('trigger_type')}".lower().encode()).hexdigest()
    lat, lng, county = geocode(rec)
    rec["lat"], rec["lng"], rec["county"] = lat, lng, county
    rec["region"] = regions.resolve(rec)   # always a US state / province / UK nation (or None)
    rec["trigger_type"] = dedupe.canon_trigger(rec.get("trigger_type")) or "Under investigation"
    # same event under a different name / wording / date? fold it into the existing record
    match = dedupe.find_match(con, rec)
    if match is not None:
        return dedupe.merge_into(con, match, rec, now)
    cur = con.execute("SELECT outcome_status FROM incidents WHERE dedup_key=?", (key,))
    existing = cur.fetchone()
    if existing is None:
        con.execute("""INSERT INTO incidents
          (dedup_key, facility_name, facility_type, town, region, county, country, lat, lng, date,
           trigger_type, protective_action, outcome_status, injuries, schools_affected,
           cluster_hint, cluster_id, confidence, evidence_quote, source_domain, source_url,
           first_seen, last_updated)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
          (key, rec.get("facility_name"), rec.get("facility_type"), rec.get("town"), rec.get("region"),
           county, rec.get("country"), lat, lng, rec.get("date"), rec.get("trigger_type"),
           rec.get("protective_action"), rec.get("outcome_status"), rec.get("injuries"),
           rec.get("schools_affected"), rec.get("cluster_hint"), slug(rec.get("cluster_hint")),
           rec.get("confidence"), rec.get("evidence_quote"), rec.get("_domain"), rec.get("_url"),
           now, now))
        new_id = con.execute("SELECT id FROM incidents WHERE dedup_key=?", (key,)).fetchone()[0]
        con.execute("INSERT OR IGNORE INTO incident_sources(incident_id,url,domain,added) VALUES (?,?,?,?)",
                    (new_id, rec.get("_url"), rec.get("_domain"), now))
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
def export(con, last_run=None):
    flags, summary = signals.compute(con)
    rows = con.execute("""SELECT id, country, date, facility_name, town, region, facility_type,
        trigger_type, protective_action, outcome_status, cluster_hint, evidence_quote, lat, lng,
        source_domain, source_url,
        (SELECT COUNT(*) FROM incident_sources s WHERE s.incident_id = incidents.id), county
        FROM incidents ORDER BY date DESC""").fetchall()
    incidents = [{
        "id": r[0], "country": r[1], "date": r[2], "school": r[3], "city": r[4], "state": r[5],
        "sector": r[6], "type": r[7], "response": r[8], "outcome": r[9], "cluster": r[10] or "",
        "notes": r[11] or "", "lat": r[12], "lng": r[13], "src": r[14], "url": r[15], "sources": r[16] or 1,
        "county": r[17], **({"signals": flags[r[0]]} if r[0] in flags else {})
    } for r in rows]
    doc = {"generated": datetime.datetime.utcnow().isoformat() + "Z",
           "count": len(incidents), "incidents": incidents, "signals": summary}
    if last_run is not None:
        doc["last_run"] = last_run   # self-reported run stats; the board ignores this key
    json.dump(doc, open(OUT, "w"), indent=2)
    return len(incidents)

# ----------------------------------------------------------------------------- run
def _meta_get(con, key):
    con.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
    row = con.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row[0] if row else None

def run(mock=False):
    con = init_db()
    now = datetime.datetime.utcnow().isoformat()
    # One-time deep backfill: the first live run on the updated engine wipes any old
    # rows and rebuilds the feed from a wide window, then flags itself done so every
    # later run is a normal tight incremental. The flag lives in the committed DB, so
    # it persists automatically — no workflow edits, nothing to trigger by hand.
    backfill = (not mock) and _meta_get(con, "backfill_version") != BACKFILL_VERSION
    if backfill:
        con.execute("DELETE FROM incidents")
        con.execute("DELETE FROM seen_articles")
        con.commit()
        days, maxrecords = 180, 80
        print("BACKFILL: one-time clean rebuild over a %dd window (scope: %s)" % (days, BACKFILL_VERSION))
    else:
        days = maxrecords = None  # normal run: env vars if set, else 3d / 60-per-fetch
    if _meta_get(con, "scope_version") != SCOPE_VERSION:
        apply_scope(con)
        con.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('scope_version', ?)", (SCOPE_VERSION,))
        con.commit()
    if _meta_get(con, "region_version") != regions.VERSION:
        regions.fix_all(con)
        con.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('region_version', ?)", (regions.VERSION,))
        con.commit()
    if _meta_get(con, "types_version") != TYPES_VERSION:
        reclassify_types(con)
        con.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('types_version', ?)", (TYPES_VERSION,))
        con.commit()
    if not mock and _meta_get(con, "county_version") != COUNTY_VERSION:
        backfill_counties(con)
        con.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('county_version', ?)", (COUNTY_VERSION,))
        con.commit()
    if _meta_get(con, "dedupe_version") != dedupe.VERSION:
        while dedupe.cleanup(con):
            pass
        con.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('dedupe_version', ?)", (dedupe.VERSION,))
        con.commit()
    articles = ingest_mock() if mock else ingest_live(days, maxrecords)
    gapfill = (not mock) and (not backfill) and _meta_get(con, "gapfill_version") != GAPFILL_VERSION
    if gapfill and articles:
        print("GAPFILL: one-time sweep of %s..%s (%s)" % (GAPFILL_WINDOW + (GAPFILL_VERSION,)))
        have = {a["url"] for a in articles}
        articles += [a for a in ingest_gap(*GAPFILL_WINDOW) if a["url"] not in have]
    if not mock and not articles:
        print("\n!!! INGEST FAILURE: 0 articles came back from every Google News edition.\n"
              "    Google is most likely throttling/blocking this runner's IP. Nothing was classified and the\n"
              "    feed was NOT updated. This run exits non-zero on purpose so it shows up RED. (exit 2)")
        sys.exit(2)
    stats = {"ingested": len(articles), "skipped_seen": 0, "recognized": 0, "new": 0, "updated": 0, "rejected": 0, "errors": 0}
    attempted = 0
    for a in articles:
        url = a.get("url")
        if url and con.execute("SELECT 1 FROM seen_articles WHERE url=?", (url,)).fetchone():
            stats["skipped_seen"] += 1
            continue
        try:
            attempted += 1
            res = classify_mock(a) if mock else classify_live(a)
            if url:
                con.execute("INSERT OR IGNORE INTO seen_articles(url, seen_at) VALUES (?,?)", (url, now))
            if not res or not res.get("include"):
                stats["rejected"] += 1
                continue
            for rec in (res.get("records") or []):
                if not rec.get("facility_name") or not rec.get("date"):
                    continue  # skip incomplete records
                rec["country"] = norm_country(rec.get("country"))
                if rec["country"] not in ALLOWED_COUNTRIES or is_republic_of_ireland(rec):
                    stats["rejected"] += 1
                    continue  # US, Canada and UK only (backstop for the prompt)
                rec["_domain"] = a.get("domain"); rec["_url"] = a.get("url")
                outcome = upsert(con, rec)
                stats["recognized"] += 1
                if outcome in ("new", "updated"):
                    stats[outcome] += 1
        except FatalClassifyError as e:
            con.commit()
            print("\n!!! CLASSIFY FAILURE (fatal): %s\n"
                  "    Check the ANTHROPIC_API_KEY repository secret and the Anthropic account's credits.\n"
                  "    Exiting non-zero on purpose so this shows up RED. (exit 3)" % e)
            sys.exit(3)
        except Exception as e:
            stats["errors"] += 1
            print("skip article (%s): %s" % (a.get("url"), e))
            continue
    assign_clusters(con)
    if backfill:
        con.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('backfill_version', ?)", (BACKFILL_VERSION,))
    if gapfill:
        con.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('gapfill_version', ?)", (GAPFILL_VERSION,))
    con.commit()
    last_run = {**stats, "attempted": attempted, "backfill": backfill, "gapfill": gapfill, "routes": ROUTE_LOG,
                "engine": "v9-signals", "ran_at": datetime.datetime.utcnow().isoformat() + "Z"}
    total = export(con, last_run)
    print(json.dumps({**last_run, "total_in_db": total, "output": OUT}, indent=2))
    if not mock and attempted >= 5 and stats["recognized"] == 0 and stats["errors"] >= attempted * 0.5:
        print("\n!!! CLASSIFY DEGRADED: %d of %d classification attempts errored and nothing was recognized.\n"
              "    This is almost always an API key / credits problem. Exiting non-zero so it shows RED. (exit 4)"
              % (stats["errors"], attempted))
        sys.exit(4)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--mock", action="store_true", help="run offline against fixtures.json")
    run(mock=ap.parse_args().mock)
