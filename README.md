# Bitwarden CLI compromise: package integrity and loader analysis

Static analysis of the recovered `bw_setup.js`, package entry points, and declared/embedded version mismatch for `@bitwarden/cli@2026.4.0`.

The study verifies:

- `preinstall` and the `bw` binary both route execution to the loader;
- the outer package claims 2026.4.0 while embedded application metadata references 2026.3.0;
- installed Bun suppresses the second stage through an early return; and
- a pure-Node ZIP extraction fallback remains available.

The recovered loader matches Aikido's published loader hash `37f34aa3b86db6898065f3ca886031978580a15251f2576f6d24c3b778907336`.

Raw and recovered analysis artifacts are excluded through `.gitignore`.

## Reproduce

```bash
python3 tools/scan_package.py \
  evidence/bw_setup.js \
  evidence/package.json \
  evidence/embedded-metadata.json
```

See `report.md` and `analysis/validation.json` for the evidence and altered-manifest negative control.
