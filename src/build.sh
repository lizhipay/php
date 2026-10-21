#!/usr/bin/env bash
# Assembles the distributable updater: template + embedded backport patches.
# Source of truth is patches/php-<branch>.patch; this embeds them (gzip+base64)
# into the self-contained output script.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
patches="$repo/patches"
out=${1:?usage: build.sh <output-path>}

python3 -I - "$here/bt-php-security-update.template.sh" "$patches" "$out" <<'PY'
import sys, io, pathlib, gzip, base64
template, patches, out = sys.argv[1], pathlib.Path(sys.argv[2]), sys.argv[3]
text = pathlib.Path(template).read_text(encoding="utf-8")

def gz(raw):  # deterministic: fixed mtime so the built script is reproducible
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=9, mtime=0) as f:
        f.write(raw)
    return buf.getvalue()

for tag, branch in (("74", "7.4"), ("80", "8.0"), ("81", "8.1")):
    raw = (patches / f"php-{branch}.patch").read_bytes()
    blob = base64.encodebytes(gz(raw)).decode("ascii").strip()
    text = text.replace(f"__BACKPORT_BLOB_{tag}__", blob)
assert "__BACKPORT_BLOB_" not in text, "a backport blob placeholder was left unfilled"
pathlib.Path(out).write_text(text, encoding="utf-8")
PY
chmod 755 "$out"
echo "built $out"
