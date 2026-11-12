#!/usr/bin/env bash
# Optional preparation inside the checkout, on the VM or inside Docker.
# Capture now creates this folder automatically; no Docker settings are changed.
set -euo pipefail

if [[ "${1:---prepare}" != "--prepare" || "$#" -gt 1 ]]; then
    printf 'Usage: %s [--prepare]\n' "$0" >&2
    printf 'No restart or extra mount is needed; capture uses the checkout mount.\n' >&2
    exit 2
fi

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_directory="$(cd -- "$script_directory/../../.." && pwd)"
if [[ ! -f "$repository_directory/tests/topotests/lib/topogen.py" ]]; then
    printf 'Run this script from the FRR checkout version of this file.\n' >&2
    exit 1
fi
results_root="$repository_directory/capstone_results"
mkdir -p -- "$results_root"
chmod 0777 -- "$results_root"
printf 'Repository results folder is ready: %s\n' "$results_root"
printf 'Capture creates it automatically. No rebuild or container recreation is needed.\n'
