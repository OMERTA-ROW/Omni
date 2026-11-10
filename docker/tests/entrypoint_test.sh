#!/bin/sh
# Run as root (needs chown + setpriv): sh docker/tests/entrypoint_test.sh
set -u
EP="$(cd "$(dirname "$0")/.." && pwd)/entrypoint.sh"
[ "$(id -u)" = "0" ] || { echo "run as root"; exit 2; }
pass=0; failn=0
ok()  { pass=$((pass+1)); echo "ok   - $1"; }
bad() { failn=$((failn+1)); echo "FAIL - $1"; }
mk()  { T="$(mktemp -d)"; chmod 755 "$T"; }
run() { OMNI_LINK_AUDIT_DIR="$1" sh "$EP" sh -c 'echo uid=$(id -u) gid=$(id -g)'; }
st()  { stat -c '%u:%g %a' "$1"; }

mk; out="$(run "$T/audit" 2>&1)"; rc=$?
[ $rc = 0 ] && [ "$(st "$T/audit")" = "10001:10001 700" ] && [ "$out" = "uid=10001 gid=10001" ] \
  && ok "fresh storage: created 0700 owned 10001, app runs as 10001" || bad "fresh storage ($rc: $out)"

mk; mkdir "$T/audit"; echo keep > "$T/audit/link.jsonl"; chmod 600 "$T/audit/link.jsonl"; chmod 700 "$T/audit"
run "$T/audit" >/dev/null 2>&1; rc=$?
[ $rc = 0 ] && [ "$(cat "$T/audit/link.jsonl")" = keep ] && [ "$(st "$T/audit/link.jsonl")" = "10001:10001 600" ] \
  && ok "existing storage: contents preserved, ownership fixed" || bad "existing storage"

mk; mkdir "$T/audit"; chmod 777 "$T/audit"; echo keep > "$T/audit/link.jsonl"; chmod 666 "$T/audit/link.jsonl"
run "$T/audit" >/dev/null 2>&1; rc=$?
[ $rc = 0 ] && [ "$(st "$T/audit")" = "10001:10001 700" ] && [ "$(st "$T/audit/link.jsonl")" = "10001:10001 600" ] && [ "$(cat "$T/audit/link.jsonl")" = keep ] \
  && ok "wrong permissions tightened, data kept" || bad "wrong permissions"

mk; mkdir "$T/audit"; mkfifo "$T/audit/link.jsonl"
run "$T/audit" >/dev/null 2>&1; rc=$?
[ $rc != 0 ] && ok "audit file not regular: rejected" || bad "non-regular audit file accepted"

mk; mkdir "$T/real"; ln -s "$T/real" "$T/audit"
run "$T/audit" >/dev/null 2>&1; rc=$?
[ $rc != 0 ] && [ "$(st "$T/real")" = "0:0 755" ] && ok "symlinked audit dir: rejected, target untouched" || bad "symlink dir"

mk; mkdir "$T/real"; ln -s "$T/real" "$T/link"
run "$T/link/audit" >/dev/null 2>&1; rc=$?
[ $rc != 0 ] && [ ! -e "$T/real/audit" ] && ok "symlinked parent: rejected, nothing created" || bad "symlink parent"

mk; mkdir "$T/audit"; echo x > "$T/target"; ln -s "$T/target" "$T/audit/link.jsonl"
run "$T/audit" >/dev/null 2>&1; rc=$?
[ $rc != 0 ] && [ "$(st "$T/target")" != "10001:10001 600" ] && ok "symlinked audit file: rejected" || bad "symlink file"

mk; run "$T/missing/audit" >/dev/null 2>&1; rc=$?
[ $rc != 0 ] && [ ! -e "$T/missing" ] && ok "missing parent (unmounted volume): fails closed" || bad "missing parent"

mk; touch "$T/audit"; run "$T/audit" >/dev/null 2>&1; rc=$?
[ $rc != 0 ] && ok "audit path is a file: rejected" || bad "file path"

mk; OMNI_LINK_AUDIT_DIR="relative/audit" sh "$EP" true >/dev/null 2>&1; rc=$?
[ $rc != 0 ] && ok "relative path: rejected" || bad "relative path"

mk; OMNI_LINK_AUDIT_DIR="$T/a/../audit" sh "$EP" true >/dev/null 2>&1; rc=$?
[ $rc != 0 ] && ok "non-normalised path: rejected" || bad "dotdot"

# Startup failure: failed init must not start the command.
mk; touch "$T/audit"; rm -f "$T/started"
OMNI_LINK_AUDIT_DIR="$T/audit" sh "$EP" sh -c "touch '$T/started'" >/dev/null 2>&1; rc=$?
[ $rc != 0 ] && [ ! -e "$T/started" ] && ok "init failure: command never started" || bad "command started despite failure"

sh "$EP" >/dev/null 2>&1; rc=$?
[ $rc != 0 ] && ok "no command: fails" || bad "no command"

mk; unset OMNI_LINK_AUDIT_DIR; out="$(sh "$EP" sh -c 'echo $(id -u)' 2>&1)"
[ "$out" = 10001 ] && ok "audit dir unset: app still starts as 10001" || bad "unset ($out)"

# A synthetic command exercises inbox-only storage setup without starting a service.
mk
BIN="$T/omni-inbox"
printf '#!/bin/sh\nprintf "%%s:%%s" "$(id -u)" "$(stat -c "%%u:%%g %%a" "$OMNI_DATA_DIR")"\ntouch "$OMNI_DATA_DIR/probe"\n' > "$BIN"
chmod 755 "$BIN"
DATA="$T/jobs"
out="$(OMNI_DATA_DIR="$DATA" sh "$EP" "$BIN" 2>&1)"; rc=$?
[ $rc = 0 ] && [ "$out" = "10001:10001:10001 700" ] && [ "$(stat -c '%u' "$DATA/probe")" = 10001 ] \
  && ok "inbox: creates private service-owned writable data directory" || bad "inbox data ($rc: $out)"

chmod 777 "$DATA"
out="$(OMNI_DATA_DIR="$DATA" sh "$EP" "$BIN" 2>&1)"; rc=$?
[ $rc = 0 ] && [ "$(st "$DATA")" = "10001:10001 700" ] \
  && ok "inbox: tightens existing data directory" || bad "inbox data permissions ($rc: $out)"

ln -s "$DATA" "$T/data-link"
OMNI_DATA_DIR="$T/data-link" sh "$EP" "$BIN" >/dev/null 2>&1; rc=$?
[ $rc != 0 ] && ok "inbox: rejects symlinked data directory" || bad "inbox data symlink"

OMNI_DATA_DIR="$T/data-link/jobs" sh "$EP" "$BIN" >/dev/null 2>&1; rc=$?
[ $rc != 0 ] && ok "inbox: rejects symlinked data parent" || bad "inbox data parent"

for path in relative / "$T/missing/jobs" "$T/a/../jobs"; do
  OMNI_DATA_DIR="$path" sh "$EP" "$BIN" >/dev/null 2>&1; rc=$?
  [ $rc != 0 ] && ok "inbox: rejects unsafe path $path" || bad "inbox unsafe path $path"
done

if [ ! -e /data ]; then
  unset OMNI_DATA_DIR
  sh "$EP" "$BIN" >/dev/null 2>&1; rc=$?
  [ $rc != 0 ] && [ ! -e /data ] && ok "inbox: missing /data fails without ephemeral fallback" || bad "inbox missing mount"
else
  [ -d /data ] || bad "/data fixture must be a directory"
fi

chmod 755 "$DATA"
setpriv --reuid=10001 --regid=10001 --clear-groups -- env OMNI_DATA_DIR="$DATA" sh "$EP" "$BIN" >/dev/null 2>&1; rc=$?
[ $rc != 0 ] && ok "inbox: nonroot rejects incorrect data permissions" || bad "inbox nonroot data"

echo "passed=$pass failed=$failn"; [ "$failn" = 0 ]
