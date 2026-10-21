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

branches = sorted(
    (m.group(1) for p in patches.glob("php-*.patch")
     for m in [re.fullmatch(r"php-(\d+\.\d+)\.patch", p.name)] if m),
    key=lambda b: [int(x) for x in b.split(".")],
)
if not branches:
    sys.exit("no patches/php-<branch>.patch files found")

sha_lines, cases = [], []
for b in branches:
    raw = (patches / f"php-{b}.patch").read_bytes()
    sha_lines.append(f'BACKPORT_SHA256[{b}]={hashlib.sha256(raw).hexdigest()}')
    blob = base64.encodebytes(gz(raw)).decode("ascii").strip()
    cases.append(f"\t{b}) cat <<'BLOB'\n{blob}\nBLOB\n\t\t;;")

dispatch = "backport_blob() {\n\tcase \"$1\" in\n" + "\n".join(cases) + "\n\tesac\n}"

text = text.replace("__BACKPORT_SHA256_ASSIGN__", "\n".join(sha_lines))
text = text.replace("__BACKPORT_BLOBS__", dispatch)
for leftover in ("__BACKPORT_SHA256_ASSIGN__", "__BACKPORT_BLOBS__", "__BACKPORT_BLOB_"):
    assert leftover not in text, f"unfilled placeholder: {leftover}"
pathlib.Path(out).write_text(text, encoding="utf-8")
print("embedded branches:", ", ".join(branches))
PY
chmod 755 "$out"
echo "built $out"
