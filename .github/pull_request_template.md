## Summary

Describe what changed and why.

## Scope

- [ ] Single concern PR (no unrelated changes)
- [ ] Docs updated when architecture/privacy behavior changed

## Validation

- [ ] `dotnet build IronTrace.sln -c Release`
- [ ] `dotnet test IronTrace.sln -c Release`

## Risk and security

- [ ] No fake success paths were introduced
- [ ] No sensitive data/secrets were added
- [ ] Privacy expectations remain intact (serial hash default, consented upload)
