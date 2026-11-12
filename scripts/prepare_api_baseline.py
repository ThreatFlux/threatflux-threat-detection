#!/usr/bin/env python3
"""Prepare an authenticated registry baseline without changing its Rust API.

Registry semver baselines resolve today's dependency graph. YARA-X 1.23 can
resolve RSA 0.10 without enabling its newly gated public PKCS#1 verifier, so
the original 0.2.3 manifest cannot generate rustdoc. Add only that dependency
feature to a checksum-verified copy of the published baseline. Candidate and
baseline continue to be checked with every feature enabled.
"""

import hashlib
from http.client import HTTPSConnection
import io
import json
from pathlib import Path
import re
import sys
import tarfile
import tomllib
from urllib.parse import urlsplit


def download(url):
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in {"index.crates.io", "static.crates.io"}
        or parsed.netloc != parsed.hostname
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("baseline downloads require an approved crates.io HTTPS host")
    connection = HTTPSConnection(parsed.hostname, timeout=60)
    try:
        connection.request("GET", parsed.path, headers={"User-Agent": "ThreatFlux-public-api-baseline"})
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError(f"baseline download failed with HTTP {response.status}")
        return response.read()
    finally:
        connection.close()


def prepare(destination):
    name = "threatflux-threat-detection"
    index = "https://index.crates.io/th/re/" + name
    entries = [json.loads(line) for line in download(index).splitlines()]
    stable = [
        entry for entry in entries
        if not entry.get("yanked")
        and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", entry["vers"])
    ]
    entry = max(stable, key=lambda item: tuple(map(int, item["vers"].split("."))))
    version = entry["vers"]
    archive = download(f"https://static.crates.io/crates/{name}/{name}-{version}.crate")
    checksum = hashlib.sha256(archive).hexdigest()
    if checksum != entry["cksum"]:
        raise ValueError("published baseline archive does not match its registry checksum")

    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as source:
        source.extractall(destination, filter="data")
    baseline = destination / f"{name}-{version}"
    manifest = baseline / "Cargo.toml"
    text = manifest.read_text(encoding="utf-8")
    metadata = tomllib.loads(text)
    if metadata["package"]["name"] != name or metadata["package"]["version"] != version:
        raise ValueError("published baseline manifest does not match its registry identity")
    # New releases already carry the feature fix. Never replace a baseline's
    # existing RSA declaration or alter source signatures and exports.
    if "rsa" not in metadata.get("dependencies", {}):
        text += '\n[dependencies.rsa]\nversion = "0.10.0"\nfeatures = ["pkcs1v15"]\n'
        manifest.write_text(text, encoding="utf-8")
    print(f"Published API baseline: {name} {version}, sha256 {checksum}")
    return baseline.resolve()


if __name__ == "__main__":
    baseline = prepare(Path(sys.argv[1]))
    with Path(sys.argv[2]).open("a", encoding="utf-8") as output:
        output.write(f"root={baseline}\n")
