# OnScene Technologies — Intelligence Desk engine

A self-running recognition engine for the Incident Awareness resource. It reads public news,
uses Claude to decide what's a real school/campus safety incident, de-duplicates and clusters
what it finds in a SQLite database, and writes `incidents.json` — the feed the board reads.

**No server and nobody feeding it by hand.** GitHub Actions runs it on a schedule and commits
the refreshed feed. You maintain a Python script and a SQL table — not infrastructure.

---

## What's in here

| File | What it is |
|---|---|
| `engine.py` | The whole pipeline: ingest → classify → de-dup/cluster → export |
| `schema.sql` | The SQLite table (also your "how many / what's the trend" query surface) |
| `requirements.txt` | One dependency: the Anthropic SDK |
| `.github/workflows/run.yml` | The hourly cron that runs it and commits the feed |
| `fixtures.json` | Sample articles for the offline test (not used in live runs) |
| `incidents.json` | The output feed the board reads (created on first run) |

---

## Prove it works offline (30 seconds, no key)

```bash
python engine.py --mock
```
You'll see it ingest the sample articles, **recognize the real incidents, reject the trend piece and
the weather story**, and write `incidents.json`. Run it twice — the second run reports `new: 0`
because de-duplication kicks in. Query the store like any database:

```bash
sqlite3 incidents.db "SELECT country, trigger_type, COUNT(*) FROM incidents GROUP BY 1,2;"
```

## Do a live run (needs your key)

```bash
export ANTHROPIC_API_KEY="sk-ant-..."      # create one at console.anthropic.com
python engine.py
```
This pulls live news from GDELT, classifies each story with Claude, and updates the feed.

---

## Put it on autopilot (GitHub Actions — the no-server part)

1. **Push these files to your repo** (keep them at the repo root).
2. **Add your key as a secret:** repo → *Settings → Secrets and variables → Actions → New repository secret*.
   Name it `ANTHROPIC_API_KEY`, paste your key.
3. **Turn Actions on** (Actions tab → enable workflows). The job now runs hourly, and you can hit
   *Run workflow* any time to fire it manually.
4. **Serve the feed:** *Settings → Pages*, serve from your default branch. Your feed is then live at
   `https://<you>.github.io/<repo>/incidents.json`.
5. **Point the board at that URL** (the board fetches `incidents.json`), and embed the board on the
   Framer `/intelligence` page.

That's the whole loop: every hour it reads the news, updates the feed, and the page refreshes — on its own.

---

## Cost (rough)

- **Classification:** a small "haiku"-class model at a few hundred articles a day is on the order of
  cents per day. It's the only recurring charge.
- **GitHub Actions + Pages:** free tier covers this comfortably.
- **GDELT:** free.

## Tuning (all in `engine.py`, plain English — no rebuild)

- **What it looks for:** widen or narrow the `QUERY` terms, and edit the `SYSTEM_PROMPT` inclusion rule
  (it's the recognition rule in prose — change a sentence, change the scope).
- **Cadence:** change the `cron` line in `run.yml`.
- **Sectors:** the prompt already anticipates Workplace and Venue — add them to the terms when you expand.

## Honest notes

- GDELT's article API returns headlines; for richer extraction, add a full-text fetch step before
  classifying (a few lines). Headlines alone already classify surprisingly well.
- The SQLite file is committed each run for persistence. At this scale that's fine; if the table grows
  large, move the store to a hosted Postgres (e.g. Supabase free tier) — the engine logic doesn't change.
- Records mature: an "Under investigation" incident is promoted when a later story confirms it a hoax
  or real. That's why it's a database, not a one-shot scrape.
