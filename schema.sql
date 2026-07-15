-- OnScene Technologies · Intelligence Desk — incident store
-- SQLite. One row per (facility, incident). The board reads an export of this table;
-- you can also query it directly for the "how many / what's the trend" reference layer.

CREATE TABLE IF NOT EXISTS incidents (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  dedup_key      TEXT UNIQUE,          -- facility|date|trigger, lowercased+hashed: prevents duplicates across outlets
  facility_name  TEXT NOT NULL,
  facility_type  TEXT,                 -- K-12 | Higher Ed | Workplace | Venue
  town           TEXT,
  region         TEXT,                 -- US state or UK county/nation
  country         TEXT,                -- US | UK
  lat            REAL,
  lng            REAL,
  date           TEXT,                 -- YYYY-MM-DD
  trigger_type   TEXT,                 -- Swatting / Active-Shooter Hoax | Bomb Threat | Weapon / Intruder | Credible Threat | Actual Violence | Non-threat safety cause
  protective_action TEXT,              -- Lockdown | Lockout/Secure | Shelter-in-place | Evacuation | Invacuation | Early dismissal | Closure | None
  outcome_status TEXT,                 -- Confirmed hoax | Under investigation | Confirmed real | Resolved – no cause found
  injuries       INTEGER,
  schools_affected INTEGER,
  cluster_hint   TEXT,                 -- free text: region + window + trigger; used to link a wave
  cluster_id     TEXT,                 -- assigned by the clustering pass
  confidence     REAL,                 -- 0..1
  evidence_quote TEXT,
  source_domain  TEXT,
  source_url     TEXT,
  first_seen     TEXT,                 -- when the engine first logged it (UTC ISO)
  last_updated   TEXT                  -- when a record was last revised (status maturing, etc.)
);

CREATE INDEX IF NOT EXISTS idx_incidents_date    ON incidents(date);
CREATE INDEX IF NOT EXISTS idx_incidents_region  ON incidents(region);
CREATE INDEX IF NOT EXISTS idx_incidents_cluster ON incidents(cluster_id);
CREATE INDEX IF NOT EXISTS idx_incidents_country ON incidents(country);
