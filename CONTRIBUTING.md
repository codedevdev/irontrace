# Contributing

## Development setup

1. Install .NET 10 SDK
2. Clone this repository
3. `dotnet restore IronTrace.sln && dotnet build IronTrace.sln -c Release && dotnet test IronTrace.sln -c Release`

Or use the helper script:

```powershell
.\scripts\build.ps1
.\scripts\build.ps1 -Publish   # local win-x64 publish
```

## CI / CD

Every pull request and push to `main` runs GitHub Actions:

| Workflow | Purpose |
|----------|---------|
| [CI](.github/workflows/ci.yml) | Restore, build, test, NuGet vulnerability gate |
| [Release](.github/workflows/release.yml) | Publish `IronTrace.exe` + `irontrace.exe`, zip, upload artifact |
| [Security](.github/workflows/security.yml) | Gitleaks secret scan + dependency audit (weekly + PRs) |

**Pull requests** must pass `CI` and `Security` before merge.

**Nightly builds:** each push to `main` uploads `IronTrace-nightly-win-x64` (7-day retention) from the Release workflow.

**Stable releases:** tag with semver and push:

```powershell
git tag v0.7.1
git push origin v0.7.1
```

This creates a [GitHub Release](https://github.com/codedevdev/irontrace/releases) with `IronTrace-{version}-win-x64.zip`.

`IronTrace.Driver` (WDK/KMDF) is **not** built in CI — lab-only, see [src/IronTrace.Driver/README.md](src/IronTrace.Driver/README.md).

## Coding standards

- Nullable enabled
- Async with cancellation tokens
- No business logic in WPF code-behind
- No silent `catch (Exception)`
- Unimplemented features stay Planned, Unsupported, or NotImplemented. No fake success paths.

## Pull requests

- Keep PRs focused on one concern
- Include or adjust unit tests for parsers, risk mapping, and report serialization
- Update docs when architecture or privacy behavior changes

## Research code

Do not vendor GPL or offensive DMA tooling. Write learnings under `docs/research/` instead.
