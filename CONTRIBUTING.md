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

## Research code

Do not vendor GPL or offensive DMA tooling. Write learnings under `docs/research/` instead.
