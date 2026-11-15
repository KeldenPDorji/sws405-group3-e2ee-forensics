#!/usr/bin/env bash
# SWS405 Group 3 lab helper (Signal on a rooted Android emulator).
# Run from Terminal inside the g3-lab folder:   bash scripts/g3.sh <command> [args]
#
#   env                      lab setup summary (host, emulator, root, Signal, tools)
#   mark <ID>                log the time you just did a scripted action (logs/activity_log.csv)
#   stop-app                 force-stop Signal; show airplane mode
#   fs <ID>                  file-system acquisition: tar of Signal data, media, notification history
#   adb-backup <ID>          logical acquisition: adb backup (confirm on the emulator screen)
#   signal-backup <ID>       pull the newest Signal on-device backup from /sdcard/Download
#   decrypt <ID> <passphrase>   decrypt Signal backup <ID> with its 30-digit passphrase
#
# Every acquisition is hashed into logs/hash_log.csv. Details go to logs/acquisition.log.
set -uo pipefail
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.." || exit 1
mkdir -p evidence work logs outputs tools

if [[ -x .venv/bin/python ]]; then PY=(.venv/bin/python)
elif command -v python3.12 >/dev/null 2>&1; then PY=(python3.12)
else PY=(python3); fi
G3PY=("${PY[@]}" scripts/g3.py)
LOG=logs/acquisition.log
PKG=org.thoughtcrime.securesms
if command -v signalbackup-tools >/dev/null 2>&1; then SIGTOOL=signalbackup-tools
else SIGTOOL=tools/signalbackup-tools_win.exe; fi

log() { echo "[$(date '+%F %T %z')] [$(hostname)] [$(whoami)] $*" >> "$LOG"; }
devsh() { adb shell "$@" 2>/dev/null | tr -d '\r'; }

need_root() {
  adb root >/dev/null 2>&1
  adb wait-for-device
  if [[ "$(devsh id -u)" != "0" ]]; then
    echo "ERROR: adb is not root. The AVD must use a 'Google APIs' image, not 'Google Play'."
    exit 2
  fi
}

cmd_env() {
  need_root
  echo "== Group 3 lab setup =="
  echo "host / user : $(hostname) / $(whoami)"
  echo "OS          : macOS $(sw_vers -productVersion 2>/dev/null) $(uname -m)"
  echo "host clock  : $(date '+%F %T %z')   (UTC $(date -u '+%T'))"
  echo "device clock: $(devsh "date '+%F %T %z'")   tz=$(devsh getprop persist.sys.timezone)"
  echo "AVD         : $(adb emu avd name 2>/dev/null | tr -d '\r' | head -1) | $(devsh getprop ro.product.name) | Android $(devsh getprop ro.build.version.release) (API $(devsh getprop ro.build.version.sdk))"
  echo "build/root  : $(devsh getprop ro.build.type) $(devsh getprop ro.build.tags) | adb uid=$(devsh id -u)"
  echo "Signal      : $(devsh dumpsys package $PKG | grep -m1 versionName | sed 's/.*versionName=//')"
  echo "notif. hist.: $(devsh settings get secure notification_history_enabled) (1 = on)"
  echo "adb         : $(adb version | sed -n 2p | sed 's/Version //')"
  echo "Python      : $("${PY[@]}" --version 2>&1 | cut -d' ' -f2)   git: $(git --version | cut -d' ' -f3)"
  echo "ALEAPP      : $("${PY[@]}" tools/ALEAPP/aleapp.py --version 2>/dev/null | tail -1)"
  echo "sbt         : $("$SIGTOOL" --help 2>&1 | grep -m1 -o 'version [0-9.]*')"
  local app="/Applications/DB Browser for SQLite.app/Contents/Info"
  echo "DB Browser  : $(defaults read "$app" CFBundleShortVersionString 2>/dev/null)"
  log "env checked"
}

cmd_mark() {
  local id="${1:?usage: mark <ID>}" f=logs/activity_log.csv
  [[ -f $f ]] || echo "id,host_time_utc+06:00,host_time_utc,device_time" > "$f"
  local now
  now="$("${PY[@]}" -c "from datetime import datetime,timezone,timedelta;print(datetime.now(timezone(timedelta(hours=6))).strftime('%Y-%m-%d %H:%M:%S'))")"
  echo "$id,$now,$(date -u '+%F %T'),$(devsh "date '+%F %T %z'")" >> "$f"
  echo "marked $id at $now (UTC+06:00)"
}

cmd_stop() {
  adb shell am force-stop "$PKG"
  echo "Signal stopped | airplane_mode_on=$(devsh settings get global airplane_mode_on)"
  log "Signal force-stopped"
}

cmd_fs() {
  local id="${1:?usage: fs <ID>}"
  need_root
  local tarf="evidence/${id}_fs.tar" hashes="evidence/${id}_device_hashes.txt" out="work/$id"
  [[ -e $tarf ]] && { echo "ERROR: $tarf exists; pick a new ID"; exit 1; }
  : > "$hashes"
  for f in /data/data/$PKG/databases/signal.db /data/data/$PKG/databases/signal.db-wal; do
    local h; h="$(devsh sha256sum "$f" | cut -d' ' -f1)"
    [[ -n "$h" ]] && echo "$h  $f  $out$f" >> "$hashes"
  done
  local want=(data/data/$PKG data/media/0/Download data/media/0/Pictures data/media/0/DCIM
              data/system_ce/0/notification_history data/system/users/0/settings_secure.xml
              data/data/com.android.providers.contacts data/misc/keystore)
  local have=()
  for p in "${want[@]}"; do [[ "$(devsh "[ -e /$p ] && echo y")" == y ]] && have+=("$p"); done
  log "$id: tar of ${have[*]}"
  adb exec-out "tar -cf - -C / ${have[*]} 2>/dev/null" > "$tarf"
  mkdir -p "$out"
  tar -xf "$tarf" -C "$out" >> "$LOG" 2>&1 || log "$id: some entries could not be extracted (see above)"
  "${G3PY[@]}" hash-add "$tarf" "$id" "file-system tar"
  echo "  device hashes taken: $(( $(wc -l < "$hashes") )) files   extracted to $out/"
}

cmd_adb_backup() {
  local id="${1:?usage: adb-backup <ID>}"
  local abf="evidence/${id}_adb.ab"
  echo "Unlock the emulator and tap 'Back up my data' (leave the password empty)."
  adb backup -all -f "$abf" >> "$LOG" 2>&1
  "${G3PY[@]}" hash-add "$abf" "$id" "adb backup"
  "${G3PY[@]}" ab2tar "$abf" "work/$id"
}

cmd_signal_backup() {
  local id="${1:?usage: signal-backup <ID>}"
  need_root
  local f; f="$(devsh "ls -t /sdcard/Download/signal-*.backup 2>/dev/null | head -1")"
  if [[ -z $f ]]; then
    echo "  $id: no signal-*.backup in /sdcard/Download (check the folder chosen in Signal)"; exit 1
  fi
  local dest="evidence/${id}_signal.backup"
  echo "$(devsh sha256sum "$f" | cut -d' ' -f1)  $f  $dest" > "evidence/${id}_device_hashes.txt"
  adb pull -a "$f" "$dest" >> "$LOG" 2>&1
  "${G3PY[@]}" hash-add "$dest" "$id" "Signal on-device backup ${f##*/}"
}

cmd_decrypt() {
  local id="${1:?usage: decrypt <ID> <passphrase>}"; shift
  local pass="${*// /}"
  rm -rf "work/$id"; mkdir -p "work/$id"
  if "$SIGTOOL" "evidence/${id}_signal.backup" "$pass" --output "work/$id" --onlydb >> "$LOG" 2>&1 && [[ -s work/$id/database.sqlite ]]; then
    echo "  $id: decrypted -> work/$id/database.sqlite ($("${G3PY[@]}" sqlite-check "work/$id/database.sqlite"))"
    log "$id signal backup decrypted"
  else
    echo "  $id: decryption failed (details in $LOG)"
  fi
}

case "${1:-}" in
  env)           cmd_env ;;
  mark)          shift; cmd_mark "$@" ;;
  stop-app)      cmd_stop ;;
  fs)            shift; cmd_fs "$@" ;;
  adb-backup)    shift; cmd_adb_backup "$@" ;;
  signal-backup) shift; cmd_signal_backup "$@" ;;
  decrypt)       shift; cmd_decrypt "$@" ;;
  *) sed -n '2,12p' "$0"; exit 1 ;;
esac
