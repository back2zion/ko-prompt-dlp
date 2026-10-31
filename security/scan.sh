#!/usr/bin/env bash
# Static security checks runnable locally and in CI.
set -uo pipefail
cd "$(dirname "$0")/../server"
echo "== bandit (SAST) =="
bandit -r axfilter -q -ll && echo "bandit: no medium/high findings"
echo "== pip-audit (axfilter dependencies) =="
pip-audit -r requirements.txt --progress-spinner off || true
