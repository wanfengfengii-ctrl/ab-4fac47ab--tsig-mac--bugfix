#!/bin/sh
# Single image, role selected by first argument: edge | cleaner | verify | test
set -eu

ROLE="${1:-edge}"

case "$ROLE" in
  edge)
    exec python -m app.server
    ;;
  cleaner)
    export SERVICE_ROLE=cleaner
    exec python -m app.server
    ;;
  verify)
    exec python -m app.verify
    ;;
  test)
    exec python -m unittest discover -s tests -v
    ;;
  *)
    echo "usage: entrypoint {edge|cleaner|verify|test}" >&2
    exit 2
    ;;
esac
