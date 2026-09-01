# IronTrace API (v1)

Phase 3 MVP: challenge/nonce upload + admin review. Host: `IronTrace.Server`.

## Local stack

```powershell
docker compose up -d
# optional: use Postgres connection string in appsettings.json
dotnet run --project src/IronTrace.Server -c Release
```

Development defaults (`appsettings.json` / `appsettings.Development.json`):

- In Development, InMemory DB is enabled unless you set `IronTrace:UseInMemoryDatabase=false`
- Bootstrap keys (change in production): `IronTrace:Bootstrap:AdminKey` / `UploadKey`, or env `IRONTRACE_BOOTSTRAP_ADMIN_KEY` / `IRONTRACE_BOOTSTRAP_UPLOAD_KEY`
- OpenAPI: `/openapi/v1.json` in Development

Production / Postgres: set `ConnectionStrings:IronTrace` and run migrations (`Database.Migrate` on startup).

## Auth

`Authorization: Bearer <api-key>`

| Prefix | Scope |
|--------|-------|
| `it_upload_…` | Upload: challenges + scan upload |
| `it_admin_…` | Admin: list/detail/review + Razor `/admin` login |

Keys are stored as SHA-256 hashes (`api_keys`). Secrets are never logged.

Admin UI: `/admin/login` with Admin API key → cookie session.

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/v1/challenges` | Upload | Issue `sessionId`, `nonce` (hex), `expiresAt` (~10 min) |
| `POST` | `/v1/scans` | Upload | Upload report JSON with HMAC headers |
| `GET` | `/v1/scans?status=` | Admin | List submissions |
| `GET` | `/v1/scans/{id}` | Admin | Detail + payload |
| `PATCH` | `/v1/scans/{id}/review` | Admin | Body `{ "status": "Accepted\|Rejected\|NeedsInfo\|Pending", "notes": "…" }` |

### Upload HMAC

Headers:

- `X-IronTrace-SessionId`
- `X-IronTrace-Nonce`
- `X-IronTrace-Signature` = hex(HMAC-SHA256(apiKey, `sessionId|nonce|sha256(body)`))

Rejects: bad signature, unknown/expired/reused challenge, unsupported `schemaVersion` (accepts `1.4` … `1.0`).

Raw `serialRaw` fields are stripped server-side. Review is human-only (no auto-ban).

## Client

WPF: Upload to server after consent. Config `IronTrace:Server:BaseUrl` + Upload API key (appsettings or DPAPI `%LocalAppData%\IronTrace\keys\upload-api-key.bin`). Upload always forces `IncludeRawSerial=false`.

## Tests

`IronTrace.Server.Tests` uses `WebApplicationFactory` + EF InMemory. For real Postgres validation, run docker-compose and point `ConnectionStrings:IronTrace` at it.
