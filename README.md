# Block Logger

A query logging app for [Technitium DNS Server](https://technitium.com/dns/) that
captures *why* a query was blocked.

Technitium's Advanced Blocking app reports the blocking group and the matched
block list only as an [Extended DNS Error](https://www.rfc-editor.org/rfc/rfc8914.html)
(EDE) option in the response. The built-in query loggers discard that option, so
the stock log can tell you *that* a query was blocked but never *which group or
list* caused it. This app fixes that: it is a drop-in replacement for the
official **Query Logs (Sqlite)** app that additionally parses the EDE data and
stores it with each blocked row.

## What you get

Blocked log entries carry a marker in their `answer` field:

```
[group=family, list=OISD Big] A 0.0.0.0
```

* `group` — the Advanced Blocking group that applied (per-client group mapping
  is preserved)
* `list` — a friendly name derived from the matched `blockListUrl` (or
  `regexBlockListUrl`)

Because the app implements `IDnsQueryLogs`, enriched entries appear in
Technitium's built-in query log viewer and are served by the standard
`/api/logs/query` API, so existing tooling keeps working.

## How it works

* Implements `IDnsApplication` + `IDnsQueryLogger` + `IDnsQueryLogs`.
* Every response is queued onto a bounded channel and batch-inserted into
  `querylogs.db` (SQLite, WAL mode) by a background consumer, so logging never
  delays DNS answers.
* When a blocked response already carries an EDE option (EDNS clients), it is
  parsed directly.
* When it does not (non-EDNS clients), the consumer re-queries the name through
  `IDnsServer.DirectQueryAsync` **with the original client endpoint**, so
  Advanced Blocking applies the same group mapping, and reads the EDE from the
  re-query response. Re-queries are bounded (8 concurrent, 500 ms timeout).
* A cleanup loop deletes rows older than `maxLogDays` (and beyond
  `maxLogRecords` if set) in 10k-row batches every 15 minutes, and can reclaim
  space with incremental vacuuming.

## Install

Build a release zip (see below), then install it on your server. From the
Technitium web console: **Apps → install from zip**, or via the API:

```
POST /api/apps/install?name=Block+Logger   (multipart form, zip file in binary form data)
```

or, hosting the zip at a URL:

```
/api/apps/downloadAndInstall?name=Block+Logger&url=https://example.com/BlockLogger.zip
```

Then select it under **Settings → Logging → Query Logger → Block Logger**.

The zip must contain the flat publish output: `BlockLogger.dll`,
`BlockLogger.deps.json`, `Microsoft.Data.Sqlite.dll`, the `SQLitePCLRaw`
assemblies, `runtimes/`, and `dnsApp.config`.

Note: app binaries are not synchronized between Technitium cluster nodes;
install on each node. (`deploy.sh` automates build → package → install →
restart for a node over SSH.)

## Build

```
./fetch-refs.sh 15.5.0          # pull Technitium reference DLLs into ./lib
docker build -f Dockerfile.build -o out .
zip -jr out/BlockLogger.zip out/
```

The build targets .NET 10 (Technitium 15.x runtime). To target a different
server version, pass it to `fetch-refs.sh`.

## Configuration (`dnsApp.config`)

| option | default | meaning |
|---|---|---|
| `enableLogging` | `true` | master switch |
| `maxLogDays` | `30` | retention window |
| `maxLogRecords` | `0` | optional hard row cap, 0 = unlimited |
| `enableVacuum` | `false` | switch the DB to incremental auto-vacuum (one-time VACUUM at next startup) and reclaim free pages during cleanup cycles |
| `maxQueueSize` | `200000` | channel buffer; oldest entries drop if the consumer falls behind |
| `maxBatchSize` | `1000` | rows per SQLite insert batch |

## Notes and limits

* Re-query enrichment only sees what Advanced Blocking decides on the re-query.
  If the block state changed between the original response and the re-query
  (list update mid-window), the recorded reason reflects the re-query.
* `DirectQueryAsync` responses are documented by Technitium as not being passed
  back to query loggers, so enrichment does not recurse.
* Timestamps are stored in round-trip ("O") format. Existing databases upgrade
  in place; nothing is migrated.

## License

GPLv3 — the same license as Technitium DNS Server itself. See [LICENSE](LICENSE).
