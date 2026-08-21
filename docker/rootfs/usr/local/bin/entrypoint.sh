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

# Container-only base-dir default: unless the caller already passed --dir
# explicitly, auto-detect which of the documented mount points was used and
# hand it to cashttpd's --dir flag. This is purely a container convenience —
# it does not change cashttpd's own default (IDEA.md "Core behavior": --dir
# defaults to "." when run directly, outside a container). Checked in this
# priority order; first one that exists wins; /site is created and used if
# none of them exist.
has_dir_flag=0
for arg in "$@"; do
  case "$arg" in
    --dir | --dir=*) has_dir_flag=1 ;;
  esac
done

if [ "$has_dir_flag" -eq 0 ] && [ "$1" = "cashttpd" ]; then
  base_dir=""
  for candidate in /site /app /root/site /data/htdocs; do
    if [ -d "$candidate" ]; then
      base_dir="$candidate"
      break
    fi
  done
  [ -n "$base_dir" ] || { base_dir="/site"; mkdir -p "$base_dir"; }
  shift
  set -- cashttpd --dir "$base_dir" "$@"
fi

exec "$@"
