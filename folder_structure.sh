#!/usr/bin/env bash
set -euo pipefail

mkdir -p appsec-takehome/{config,scripts,demo/app,demo/legacy,demo/tests,tests,artifacts,docs,.github/workflows}
cd appsec-takehome
touch artifacts/.gitkeep
printf 'artifacts/*.json\nartifacts/*.sarif\nartifacts/*.md\n.bin/\n.venv/\n__pycache__/\n' > .gitignore

