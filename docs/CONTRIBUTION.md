# Contribution Guide

## Branching Policy

- `master` is protected.
- Direct pushes to `master` are blocked.
- All changes must be merged through a pull request.

## Required Checks

- The `Quality Gates` GitHub Actions check must pass before merge.

## Development Flow

1. Create a feature branch from `master`.
2. Make changes and run local checks:

```bash
make quality
```

3. Commit and push your branch.
4. Open a pull request into `master`.
5. Wait for `Quality Gates` to pass.
6. Merge the pull request.

## Notes

- Self-merge is allowed after required checks pass.
- Keep pull requests focused and small when possible.
- For deployment details, see [DEPLOY.md](./DEPLOY.md).
