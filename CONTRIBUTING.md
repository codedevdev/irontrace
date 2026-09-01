# Contributing

## Development setup

1. Install .NET 10 SDK
2. Clone this repository
3. `dotnet restore && dotnet build && dotnet test`

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

## Merge rules

- All changes go through pull requests; no direct pushes to the default branch.
- Require at least 1 approval from CODEOWNERS before merge.
- Require CI checks (`dotnet build` and `dotnet test`) to pass before merge.
- Use **Squash merge** for feature/fix branches to keep history clean.
- Use **Rebase merge** only for curated release/hotfix branches when preserving commit sequence matters.
- Delete branch after merge.

## Research code

Do not vendor GPL or offensive DMA tooling. Write learnings under `docs/research/` instead.
