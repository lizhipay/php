#!/usr/bin/env bash
# Assembles the distributable updater: template + every patches/php-<branch>.patch
# embedded (gzip+base64). Source of truth is patches/; adding a version = drop its
# .patch there and rebuild. No per-version edits to the template or this script.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
out=${1:?usage: build.sh <output-path>}

python3 -I - "$here/php-security-update.template.sh" "$repo/patches" "$out" <<'PY'
import sys, io, re, pathlib, gzip, base64, hashlib
template, patches, out = sys.argv[1], pathlib.Path(sys.argv[2]), sys.argv[3]
text = pathlib.Path(template).read_text(encoding="utf-8")

def gz(raw):  # deterministic: fixed mtime so the built script is reproducible
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=9, mtime=0) as f:
        f.write(raw)
    return buf.getvalue()

def embed(dir_, pat, fn_name, sha_name):
    found = sorted(
        (m.group(1) for p in dir_.glob(pat.replace("BRANCH", "*"))
         for m in [re.fullmatch(pat.replace("BRANCH", r"(\d+\.\d+)"), p.name)] if m),
        key=lambda b: [int(x) for x in b.split(".")],
    )
    sha, cases = [], []
    for b in found:
        raw = (dir_ / pat.replace("BRANCH", b)).read_bytes()
        sha.append(f'{sha_name}[{b}]={hashlib.sha256(raw).hexdigest()}')
        cases.append(f"\t{b}) cat <<'BLOB'\n{base64.encodebytes(gz(raw)).decode().strip()}\nBLOB\n\t\t;;")
    body = "\tcase \"$1\" in\n" + "\n".join(cases) + "\n\tesac" if cases else "\t:"
    dispatch = f"{fn_name}() {{\n{body}\n}}"
    return found, "\n".join(sha), dispatch

branches, bsha, bdispatch = embed(patches, "php-BRANCH.patch", "backport_blob", "BACKPORT_SHA256")
if not branches:
    sys.exit("no patches/php-<branch>.patch files found")
hbranches, hsha, hdispatch = embed(patches.parent / "hardening", "php-BRANCH-session-hardening.patch", "harden_blob", "HARDEN_SHA256")

text = text.replace("__BACKPORT_SHA256_ASSIGN__", bsha)
text = text.replace("__BACKPORT_BLOBS__", bdispatch)
text = text.replace("__HARDEN_SHA256_ASSIGN__", hsha)
text = text.replace("__HARDEN_BLOBS__", hdispatch)
for leftover in ("__BACKPORT_SHA256_ASSIGN__", "__BACKPORT_BLOBS__", "__BACKPORT_BLOB_",
                 "__HARDEN_SHA256_ASSIGN__", "__HARDEN_BLOBS__"):
    assert leftover not in text, f"unfilled placeholder: {leftover}"
pathlib.Path(out).write_text(text, encoding="utf-8")
print("backport branches:", ", ".join(branches))
print("hardening branches:", ", ".join(hbranches) or "(none yet)")
PY
chmod 755 "$out"
echo "built $out"
