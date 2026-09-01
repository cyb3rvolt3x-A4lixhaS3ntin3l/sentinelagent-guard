# Contributing

Thanks for helping make MCP safer.

## Develop

```bash
npm install          # installs the workspace
npm run build        # builds all three packages
npm test             # runs the full vitest suite
```

- `packages/guard-core` — the pure detection engine (zero runtime deps). New
  checks and attack fixtures go here, with a test in the corpus.
- `packages/guard-sdk` — the embeddable SDK.
- `packages/guard-proxy` — the stdio sidecar + `scan` CLI.

## Pull requests

- Keep detection logic in `guard-core` so every surface stays in agreement.
- Add a test for any new check or bugfix.
- `npm run build && npm test` must pass. Match the surrounding code style.
- By contributing you agree your work is licensed under Apache-2.0.
