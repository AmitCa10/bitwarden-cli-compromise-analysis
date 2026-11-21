#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path

EXPECTED_LOADER_SHA256 = "37f34aa3b86db6898065f3ca886031978580a15251f2576f6d24c3b778907336"


def analyze(loader_path, manifest_path, metadata_path):
    raw = loader_path.read_bytes()
    text = raw.decode("utf-8")
    manifest = json.loads(manifest_path.read_text())
    metadata = json.loads(metadata_path.read_text())
    checks = {
        "published_loader_hash": hashlib.sha256(raw).hexdigest() == EXPECTED_LOADER_SHA256,
        "preinstall_points_to_loader": manifest.get("scripts", {}).get("preinstall") == "node bw_setup.js",
        "binary_points_to_loader": manifest["bin"]["bw"] == "bw_setup.js",
        "outer_version_is_2026_4_0": manifest["version"] == "2026.4.0" == metadata["declaredPackageVersion"],
        "embedded_version_is_2026_3_0": metadata["embeddedApplicationVersion"] == "2026.3.0",
        "installed_bun_early_return": 'execFileSync("bun", ["--version"], { stdio: "ignore" });\n    return;' in text,
        "pure_node_zip_fallback": "function extractFromZip" in text and "inflateRawSync" in text,
    }
    dual_entry = checks["preinstall_points_to_loader"] and checks["binary_points_to_loader"]
    mismatch = checks["outer_version_is_2026_4_0"] and checks["embedded_version_is_2026_3_0"]
    return {
        "sample": str(loader_path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "checks": checks,
        "dual_loader_entrypoints": dual_entry,
        "version_mismatch": mismatch,
        "verdict": "dual_entrypoint_and_version_mismatch" if dual_entry and mismatch else "package_integrity_checks_not_all_matched",
    }


def main():
    parser = argparse.ArgumentParser(description="Verify Bitwarden package entry-point and version-integrity failures")
    parser.add_argument("loader", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("metadata", type=Path)
    args = parser.parse_args()
    result = analyze(args.loader, args.manifest, args.metadata)
    print(json.dumps(result, indent=2))
    raise SystemExit(1 if result["verdict"] == "dual_entrypoint_and_version_mismatch" else 0)


if __name__ == "__main__":
    main()
