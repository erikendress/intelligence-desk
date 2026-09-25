"""
Intelligence Desk: clean up the region field so the board can filter by state / province / UK nation.

The classifier sometimes writes a county ("Martin County", "Harris County, Texas") or nothing at all.
resolve() returns a proper US state, Canadian province/territory, or UK nation. It uses the
classifier's value when that is already valid, and otherwise looks the place up from its map
coordinates with OpenStreetMap (free, 1 request/second, results cached).

    python regions.py      # one-time fix of incidents.db (the engine also runs this automatically once)
"""
import re, json, time, urllib.parse, urllib.request

VERSION = "1"

US = """Alabama Alaska Arizona Arkansas California Colorado Connecticut Delaware Florida Georgia Hawaii Idaho
Illinois Indiana Iowa Kansas Kentucky Louisiana Maine Maryland Massachusetts Michigan Minnesota Mississippi
Missouri Montana Nebraska Nevada New_Hampshire New_Jersey New_Mexico New_York North_Carolina North_Dakota Ohio
Oklahoma Oregon Pennsylvania Rhode_Island South_Carolina South_Dakota Tennessee Texas Utah Vermont Virginia
Washington West_Virginia Wisconsin Wyoming District_of_Columbia Puerto_Rico""".split()
US_ABBR = """AL AK AZ AR CA CO CT DE FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS MO MT NE NV NH NJ NM NY NC ND
OH OK OR PA RI SC SD TN TX UT VT VA WA WV WI WY DC PR""".split()
CA = """Alberta British_Columbia Manitoba New_Brunswick Newfoundland_and_Labrador Nova_Scotia Ontario
Prince_Edward_Island Quebec Saskatchewan Northwest_Territories Nunavut Yukon""".split()
CA_ABBR = "AB BC MB NB NL NS ON PE QC SK NT NU YT".split()
UK = ["England", "Scotland", "Wales", "Northern Ireland"]

def _canon(names):
    return {n.replace("_", " ").lower(): n.replace("_", " ") for n in names}

VALID = {
    "United States": {**_canon(US), **{a.lower(): n.replace("_", " ") for a, n in zip(US_ABBR, US)},
                      "washington dc": "District of Columbia", "washington, d.c.": "District of Columbia",
                      "d.c.": "District of Columbia"},
    "Canada": {**_canon(CA), **{a.lower(): n.replace("_", " ") for a, n in zip(CA_ABBR, CA)},
               "labrador": "Newfoundland and Labrador", "newfoundland": "Newfoundland and Labrador",
               "québec": "Quebec", "pei": "Prince Edward Island"},
    "United Kingdom": {**_canon(UK), "n. ireland": "Northern Ireland", "ni": "Northern Ireland"},
}

def canonical(region, country):
    """'Texas', 'TX', 'Harris County, Texas' -> 'Texas'. Returns None if no valid region is in the text."""
    table = VALID.get(country)
    if not table or not region:
        return None
    r = region.strip().lower()
    if r in table:
        return table[r]
    for part in re.split(r"[,/;()]", r):          # "Harris County, Texas" / "Ontario County, New York"
        p = part.strip()
        if p in table and not p.endswith("county"):
            return table[p]
    return None

_CACHE = {}
UA = "OnSceneTechnologiesIntelligenceDesk/1.0 (contact: info@onscenetechnologies.com)"

def _get(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.load(r)
    time.sleep(1.1)                                # Nominatim usage policy: max 1 request/second
    return data

def reverse(lat, lng, country):
    """Region from map coordinates (OpenStreetMap's 'state' = US state / province / UK nation)."""
    if lat is None or lng is None or is_centroid(lat, lng):
        return None
    key = (round(lat, 3), round(lng, 3))
    if key not in _CACHE:
        try:
            d = _get("https://nominatim.openstreetmap.org/reverse?" + urllib.parse.urlencode(
                {"lat": lat, "lon": lng, "format": "json", "zoom": 5, "accept-language": "en"}))
            _CACHE[key] = (d.get("address") or {}).get("state")
        except Exception:
            _CACHE[key] = None
    return canonical(_CACHE[key], country)

def forward(town, region, country):
    """Region from a place name, for records with no coordinates."""
    q = ", ".join(x for x in [town, region, country] if x)
    if not town:
        return None     # a county name alone ("Russell County") exists in many states
    if q not in _CACHE:
        try:
            d = _get("https://nominatim.openstreetmap.org/search?" + urllib.parse.urlencode(
                {"q": q, "format": "json", "limit": 1, "addressdetails": 1, "accept-language": "en"}))
            _CACHE[q] = ((d[0].get("address") or {}).get("state")) if d else None
        except Exception:
            _CACHE[q] = None
    return canonical(_CACHE[q], country)

def resolve(rec):
    """Best region for a record dict (keys: region, country, lat, lng, town)."""
    c = rec.get("country")
    return (canonical(rec.get("region"), c)
            or reverse(rec.get("lat"), rec.get("lng"), c)
            or forward(rec.get("town"), rec.get("region"), c))

# Geocoding a bare country name returns the country's centre point, which put dozens of incidents
# with no town on a fake pin in Kansas. These points are treated as "no location".
CENTROIDS = {(39.7837, -100.4459), (61.0667, -107.9917), (54.7024, -3.2766)}

_CENTROID_SQL = " OR ".join("(round(lat,4)=%s AND round(lng,4)=%s)" % c for c in CENTROIDS)

def is_centroid(lat, lng):
    return lat is not None and lng is not None and (round(lat, 4), round(lng, 4)) in CENTROIDS

def fix_all(con, verbose=True):
    """One-time pass over the store: rewrite every region to a proper state / province / nation."""
    # drop false centre-point pins; a generic facility name ("Central High School") can't be placed reliably
    cleared = con.execute("SELECT COUNT(*) FROM incidents WHERE %s" % _CENTROID_SQL).fetchone()[0]
    con.execute("UPDATE incidents SET lat=NULL, lng=NULL WHERE %s" % _CENTROID_SQL)
    rows = con.execute("SELECT id, region, country, lat, lng, town FROM incidents").fetchall()
    changed = unresolved = 0
    for rid, region, country, lat, lng, town in rows:
        new = resolve({"region": region, "country": country, "lat": lat, "lng": lng, "town": town})
        if new != region:
            con.execute("UPDATE incidents SET region=? WHERE id=?", (new, rid))
            changed += 1
        if not new:
            unresolved += 1
    con.commit()
    if verbose:
        print("regions: %d rows, %d rewritten, %d still without a state/province; %d false centre-point pins removed"
              % (len(rows), changed, unresolved, cleared))

if __name__ == "__main__":
    import sqlite3, os
    fix_all(sqlite3.connect(os.path.join(os.path.dirname(os.path.abspath(__file__)), "incidents.db")))
