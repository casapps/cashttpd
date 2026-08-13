#!/bin/sh
# Container entrypoint: prepares runtime dirs, then hands off to the app.
# Invoked as: tini -> entrypoint.sh -> app (never bypass tini).
set -e

mkdir -p "${XDG_CACHE_HOME:-/tmp/cache}" "${XDG_STATE_HOME:-/tmp/state}"

# `docker run image --some-flag` or `docker run image serve ...` replaces
# CMD entirely, so "$@" would start with a bare flag, a subcommand word, or
# be empty — none of which are directly executable. Prepend the binary name
# unless the caller already named it explicitly or is invoking an absolute
# path (e.g. `/bin/sh` for debugging).
case "$1" in
  cashttpd | /*) ;;
  *) set -- cashttpd "$@" ;;
esac

exec "$@"
