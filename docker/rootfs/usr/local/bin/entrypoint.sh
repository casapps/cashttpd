#!/bin/sh
# Container entrypoint: prepares runtime dirs, then hands off to the app.
# Invoked as: tini -> entrypoint.sh -> app (never bypass tini).
set -e

mkdir -p "${XDG_CACHE_HOME:-/tmp/cache}" "${XDG_STATE_HOME:-/tmp/state}"

exec "$@"
