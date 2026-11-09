# vendored: vibe-preflight 1.3.0

`preflight.mjs` is the single-file scanner bundle from
[atokim4/vibe-preflight](https://github.com/atokim4/vibe-preflight) at commit `3df7b06`
(`skills/vibe-preflight/scripts/preflight.mjs`), MIT licensed (see `LICENSE`). It has no dependencies.

The audit refuses to run it if its SHA-256 differs from the value pinned in `src/scanners/preflight.ts`:

```
64adfc4ec55731cd8b909cc473d0a0a6716fab16618bb78d30c70b217ea6d35c  preflight.mjs
```

To update: copy the new bundle here, run `sha256sum preflight.mjs`, and change the pin and version in that file.
