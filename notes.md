# ThreatLens Ingestion Verification Notes

Use these commands to verify the complete RSS -> raw article -> IOC persistence flow.

## 1. Run the ingestion and IOC tests

```bash
pytest backend/tests/test_ingestion.py backend/tests/test_ioc_extraction.py -q
```

Expected output:

```text
11 passed
```

You may also see SQLAlchemy deprecation warnings about `datetime.utcnow()`.

## 2. Run the enrichment scaffold tests

If you are still working on the Phase 3.1 stubs, run:

```bash
pytest backend/tests/test_enrichment.py -q
```

Expected output right now:

```text
5 failed
```

Those failures are expected until the enrichment extractor stubs are implemented.

## 3. Watch the INFO logs during RSS ingestion

Run your normal RSS ingestion command or the Celery task that triggers it, then look for log lines like:

```text
Stored article id=125
Extracted 8 IOCs for raw_article_id=125
Persisted 8 indicators for raw_article_id=125
```

If a duplicate article is skipped, you should see:

```text
Skipped duplicate article content_hash=...
```

## 4. Verify the database contents

Open a PostgreSQL session and run:

```sql
SELECT COUNT(*) FROM indicators;
```

Expected output:

```text
 count
-------
     > 0
```

Then check counts by indicator type:

```sql
SELECT indicator_type, COUNT(*)
FROM indicators
GROUP BY indicator_type
ORDER BY indicator_type;
```

Expected output:

```text
 indicator_type | count
----------------+-------
 CVE            | ...
 IPv4           | ...
 IPv6           | ...
 Domain         | ...
 URL            | ...
 Email          | ...
 MD5            | ...
 SHA1           | ...
 SHA256         | ...
```

The exact numbers depend on your feeds, but the key point is that the table is not empty and the types match what the extractor emits.

## 5. Check indicators per article

If you want to verify the legacy article-to-indicator link directly:

```sql
SELECT ra.id, COUNT(i.id) AS indicator_count
FROM raw_articles ra
LEFT JOIN indicators i ON i.raw_article_id = ra.id
GROUP BY ra.id
ORDER BY ra.id DESC
LIMIT 10;
```

Expected output:

```text
 id  | indicator_count
-----+-----------------
 ... | ...
```

At least one recent article should show a non-zero indicator count.

## 6. What this confirms

- `RSSClient.fetch()` is producing feed XML.
- `RSSNormalizer` is turning it into `NormalizedArticle` objects.
- `FeedManager.store()` inserts the `RawArticle`.
- `session.flush()` assigns `raw_article.id` before IOC extraction.
- `IOCExtractionService.extract(raw_article)` runs for each new article.
- `persist_indicators(...)` inserts IOC rows in the same session.
- `session.commit()` persists both the article and its indicators together.
