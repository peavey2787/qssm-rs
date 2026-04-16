# Local GeoIP (privacy-first)

Preferred source: **DB-IP City Lite**.

Fetch automatically from `crates/qssm-desktop`:

```powershell
npm run geo:fetch-dbip
```

This downloads and decompresses:

- URL: `https://cdn.jsdelivr.net/npm/dbip-city-lite/dbip-city-lite.mmdb.gz`
- Output: `src-tauri/resources/dbip-city-lite.mmdb`

The backend also supports MaxMind GeoLite2 if you already have it.

Lookup paths:

1. `QSSM_GEOIP_MMDB` (preferred env var)
2. `QSSM_GEOLITE_MMDB` (legacy env var)
3. Bundled resources: `dbip-city-lite.mmdb` then `GeoLite2-City.mmdb`
4. CWD fallbacks in dev mode

If no database is present, the app still resolves your **public IP** (HTTPS) but **omits coordinates** until a local database is available.

Coordinates sent to the UI are **fuzzed by ±0.5°** in Rust before emission.

DB-IP attribution notice is in root `LEGAL.md` and shown in the desktop UI Credits section.
