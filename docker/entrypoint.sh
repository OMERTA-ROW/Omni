#!/bin/sh
# Prepares the private OMNI audit directory, then drops to the unprivileged
# runtime user. Fails closed: any problem aborts startup before the app runs.
set -eu

RUN_UID=10001
RUN_GID=10001
RUN_HOME=/home/omni

fail() { echo "entrypoint: $*" >&2; exit 1; }

[ "$#" -gt 0 ] || fail "no command given"

if [ "${1##*/}" = "omni-inbox" ]; then
  data="${OMNI_DATA_DIR:-/data}"
  case "$data" in /*) ;; *) fail "OMNI_DATA_DIR must be absolute" ;; esac
  [ "$data" != "/" ] || fail "OMNI_DATA_DIR must not be /"
  [ "$(realpath -m -s -- "$data")" = "$data" ] || fail "OMNI_DATA_DIR must be a normalised path"
  parent="$(dirname -- "$data")"
  [ -d "$parent" ] && [ "$(realpath -e -- "$parent")" = "$parent" ] || fail "data parent missing or symlinked"
  [ ! -L "$data" ] || fail "data directory is a symlink"
  if [ "$data" = "/data" ]; then
    [ -d "$data" ] || fail "mount a writable /data directory before starting the inbox"
  fi
  if [ "$(id -u)" = "0" ]; then
    if [ ! -e "$data" ]; then
      mkdir -m 0700 -- "$data" || fail "cannot create data directory"
    fi
    [ -d "$data" ] || fail "data path is not a directory"
    chown "$RUN_UID:$RUN_GID" -- "$data" || fail "chown data directory failed"
    chmod 0700 -- "$data" || fail "chmod data directory failed"
  fi
  [ -d "$data" ] && [ "$(stat -c '%u:%g %a' -- "$data")" = "$RUN_UID:$RUN_GID 700" ] || fail "data directory must be $RUN_UID:$RUN_GID mode 0700"
  export OMNI_DATA_DIR="$data"
fi

dir="${OMNI_LINK_AUDIT_DIR:-}"
if [ -n "$dir" ]; then
  case "$dir" in /*) ;; *) fail "OMNI_LINK_AUDIT_DIR must be absolute" ;; esac
  [ "$dir" != "/" ] || fail "OMNI_LINK_AUDIT_DIR must not be /"
  # Normalised path only: no '..', no '//', no trailing slash.
  [ "$(realpath -m -s -- "$dir")" = "$dir" ] || fail "OMNI_LINK_AUDIT_DIR must be a normalised path"
  # No symlink anywhere in the path (compare with the fully resolved path).
  parent="$(dirname -- "$dir")"
  [ -d "$parent" ] && [ ! -L "$parent" ] || fail "audit parent $parent missing (is the volume mounted?)"
  [ "$(realpath -e -- "$parent")" = "$parent" ] || fail "audit parent path contains a symlink"
  [ ! -L "$dir" ] || fail "audit directory is a symlink"

  if [ "$(id -u)" = "0" ]; then
    if [ ! -e "$dir" ]; then
      mkdir -m 0700 -- "$dir" || fail "cannot create audit directory"
    fi
    [ -d "$dir" ] && [ ! -L "$dir" ] || fail "audit path is not a real directory"
    chown "$RUN_UID:$RUN_GID" -- "$dir" || fail "chown audit directory failed"
    chmod 0700 -- "$dir" || fail "chmod audit directory failed"
    f="$dir/link.jsonl"
    if [ -e "$f" ] || [ -L "$f" ]; then
      [ -f "$f" ] && [ ! -L "$f" ] || fail "audit file is not a regular file"
      chown "$RUN_UID:$RUN_GID" -- "$f" || fail "chown audit file failed"
      chmod 0600 -- "$f" || fail "chmod audit file failed"
    fi
  fi

  # Verify (also the only step when not root).
  [ -d "$dir" ] && [ ! -L "$dir" ] || fail "audit path is not a real directory"
  [ "$(stat -c '%u:%g %a' -- "$dir")" = "$RUN_UID:$RUN_GID 700" ] || fail "audit directory must be $RUN_UID:$RUN_GID mode 0700"
  f="$dir/link.jsonl"
  if [ -e "$f" ] || [ -L "$f" ]; then
    [ -f "$f" ] && [ ! -L "$f" ] || fail "audit file is not a regular file"
    [ "$(stat -c '%u:%g %a' -- "$f")" = "$RUN_UID:$RUN_GID 600" ] || fail "audit file must be $RUN_UID:$RUN_GID mode 0600"
  fi
fi

if [ "$(id -u)" = "0" ]; then
  export HOME="$RUN_HOME"
  if [ "${OMNI_WORKER_ENABLED:-}" = "true" ] && [ "${1##*/}" = "omni-inbox" ]; then
    exec setpriv --reuid="$RUN_UID" --regid="$RUN_GID" --clear-groups -- "$@"
  fi
  if [ "${OMNI_SHELL_ENABLED:-}" = "true" ] && [ "${1##*/}" = "omni-inbox" ]; then
    # The inbox needs exec access to its caller-restricted setuid shell helper.
    exec setpriv --reuid="$RUN_UID" --regid="$RUN_GID" --clear-groups -- "$@"
  fi
  exec setpriv --reuid="$RUN_UID" --regid="$RUN_GID" --clear-groups --no-new-privs -- "$@"
fi
[ "$(id -u)" = "$RUN_UID" ] || fail "must run as root or uid $RUN_UID"
exec "$@"
