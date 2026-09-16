#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
mode="${1:-demo}"
port="${2:-8000}"
if [[ $# -gt 2 || ( "$mode" != demo && "$mode" != live ) || ( "$port" != 8000 && "$port" != 8011 && "$port" != 5173 ) ]]; then
  echo "사용법: bash scripts/start.sh [demo|live] [8000|8011|5173]" >&2
  exit 2
fi
if [[ ! -x .venv/bin/python || ! -f frontend/dist/index.html ]]; then
  echo "README의 프로젝트 의존성 설치 및 build를 먼저 실행해 주세요." >&2
  exit 1
fi
export UNION_MODE="$mode"
exec .venv/bin/python -m uvicorn backend.app.main:app --host 127.0.0.1 --port "$port" --workers 1 --no-access-log --no-proxy-headers
