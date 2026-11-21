# Bitwarden CLI: dual loader entry points and version-metadata mismatch

**Author:** [Amit Carmon](https://github.com/AmitCa10)

## Summary

This study verifies two package-integrity failures in the malicious `@bitwarden/cli@2026.4.0` release:

1. Both the `preinstall` lifecycle hook and the `bw` binary entry point route execution to `bw_setup.js`.
2. The outer package declares version 2026.4.0 while embedded application metadata references 2026.3.0.

The recovered loader also returns early when Bun is already installed, but includes a pure-Node ZIP parser for environments without `unzip`.

No malware was executed and no registry or C2 infrastructure was contacted.

## Evidence provenance

The recovered `bw_setup.js` was extracted from the public analysis appendix at [this gist](https://gist.github.com/N3mes1s/9c210b64760390f1ca2c451100a5ec99). It has:

- 4,292 bytes in the local recovered form; and
- SHA-256 `37f34aa3b86db6898065f3ca886031978580a15251f2576f6d24c3b778907336`.

That hash matches the loader value published by Aikido. The registry tarball was not available during this research, so the report distinguishes the recovered artifact from a direct registry download.

`evidence/package.json` contains the relevant manifest fields documented by JFrog and SafeDep; it is not represented as a complete original manifest. `embedded-metadata.json` records the outer and embedded version values documented by JFrog and StepSecurity, not a recovered `build/bw.js` file.

## Finding 1: installation and invocation both reach the loader

The documented manifest changes are:

```json
{
  "scripts": {
    "preinstall": "node bw_setup.js"
  },
  "bin": {
    "bw": "bw_setup.js"
  }
}
```

This creates two execution paths:

- `npm install` invokes the loader through `preinstall`.
- Invoking `bw` also resolves to the loader rather than the legitimate bundled CLI.

Reviewing only lifecycle fields misses the second path. Reviewing only the binary declaration misses the install-time path. Both must be considered when assessing exposure.

## Finding 2: declared and embedded versions conflict

The outer manifest identifies `2026.4.0`, while the embedded application metadata identifies `2026.3.0`. Public analyses interpret this mismatch as evidence that a legitimate older release was repackaged with a malicious wrapper rather than built cleanly from source.

This is a practical integrity check for reviewers:

- compare the root package version with embedded release metadata;
- inspect files added or changed outside the compiled application;
- do not treat a working CLI or valid package identity as proof of a clean build; and
- compare the artifact with the prior clean release when possible.

## Finding 3: installed Bun suppresses the second stage

The loader begins with:

```javascript
try {
  execFileSync("bun", ["--version"], { stdio: "ignore" });
  return;
} catch {}
```

The download and `bw1.js` execution occur only after this block. Consequently, the recovered loader does not launch its second stage when the Bun version command succeeds.

This is similar to the SAP loader's early-return behavior. Unlike that loader, however, this artifact includes `extractFromZip` and `zlib.inflateRawSync`, providing an internal extraction fallback when `unzip` is unavailable.

## Defensive guidance

- Check both `scripts` and `bin` in package manifests for unexpected entry-point changes.
- Compare outer and embedded version identifiers as part of release-integrity review.
- Treat runtime downloads during installation as security-relevant behavior even when the destination is an official project release.
- Do not infer that an artifact will execute in every environment. Bun availability and extraction support change the control flow.
- Rotate exposed credentials and inspect AI/MCP configuration files after a confirmed installation, following the vendor's incident-response guidance.

## Validation

`analysis/validation.json` contains:

| Input | Result |
| --- | --- |
| Recovered loader, documented manifest, and documented metadata | Both loader entry points and the 2026.4.0/2026.3.0 mismatch confirmed |
| Altered manifest with no `preinstall`, `bw` set to `build/bw.js`, and version 2026.3.0 | Package integrity checks do not all match |

The negative control shows that the scanner requires both the entry-point and version evidence rather than alerting on the loader alone.

## Limitations

- The registry tarball and second-stage `bw1.js` were not analyzed locally.
- The manifest and version metadata are documented excerpts, not complete original files.
- No dynamic installation, CLI invocation, payload execution, or exfiltration was attempted.
- Public reports contain different hash groupings for some artifacts; this report uses the exact recovered loader and its locally verified Aikido-matching hash rather than assuming they are interchangeable.

## Reproduce

From this directory:

```bash
python3 tools/scan_package.py \
  evidence/bw_setup.js \
  evidence/package.json \
  evidence/embedded-metadata.json
```

The scanner exits with status 1 when it confirms both loader entry points and the version mismatch.

## References

- [Aikido: compromised Bitwarden CLI](https://www.aikido.dev/blog/shai-hulud-npm-bitwarden-cli-compromise)
- [JFrog: Bitwarden CLI hijack analysis](https://research.jfrog.com/post/bitwarden-cli-hijack/)
- [SafeDep: Bitwarden CLI supply chain compromise](https://safedep.io/blog/bitwarden-cli-supply-chain-compromise)
- [StepSecurity: loader, AI credential targeting, and response guidance](https://www.stepsecurity.io/blog/bitwarden-cli-hijacked-on-npm-bun-staged-credential-stealer-targets-developers-github-actions-and-ai-tools)
- [Recovered loader appendix](https://gist.github.com/N3mes1s/9c210b64760390f1ca2c451100a5ec99)
