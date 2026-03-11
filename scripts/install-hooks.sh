#!/usr/bin/env bash
# Install git hooks from .githooks into this repo and set core.hooksPath
set -e
REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
HOOK_SRC="$REPO_ROOT/.githooks"
HOOK_DST="$REPO_ROOT/.git/hooks"
if [ ! -d "$HOOK_SRC" ]; then
  echo ".githooks directory not found"
  exit 1
fi
mkdir -p "$HOOK_DST"
cp -rT "$HOOK_SRC" "$HOOK_DST"
git config core.hooksPath .git/hooks
chmod +x "$HOOK_DST"/* || true
echo "Hooks installed to .git/hooks and core.hooksPath set."
