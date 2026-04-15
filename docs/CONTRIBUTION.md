# Contribution Guide

## Branching Policy

- `master` is protected.
- Direct pushes to `master` are blocked.
- All changes must be merged through a pull request.

## Required Checks

- The `Quality Gates` GitHub Actions check must pass before merge.
- Local push is blocked when `make quality` fails.

## Development Flow

1. Create a feature branch from `master`.
2. Ensure git hooks are installed locally:
3. Make changes and commit normally.
4. Push your branch.
5. `pre-push` runs `make quality` automatically.
6. If quality gates fail, push is rejected; fix issues and push again.
7. Open a pull request into `master`.
8. Wait for `Quality Gates` to pass in GitHub Actions.
9. Merge the pull request.

## Notes

- Self-merge is allowed after required checks pass.
- Keep pull requests focused and small when possible.
- For deployment details, see [DEPLOY.md](./DEPLOY.md).
