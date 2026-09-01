# Merge policy setup

Use these repository settings for the default branch:

1. **Branch protection**
   - Require a pull request before merging
   - Require approvals: **1**
   - Require review from CODEOWNERS: **enabled**
   - Dismiss stale approvals when new commits are pushed: **enabled**
   - Require status checks to pass before merging: **enabled**
   - Required checks: `dotnet build`, `dotnet test` (or equivalent workflow jobs)
   - Restrict who can push to matching branches: **enabled**
   - Do not allow force pushes

2. **Merge methods**
   - Allow squash merging: **enabled**
   - Allow rebase merging: **enabled** (for release/hotfix only)
   - Allow merge commits: **disabled**
   - Automatically delete head branches: **enabled**

3. **Ruleset note**
   - If using branch rulesets instead of classic protection, mirror the same requirements there.
