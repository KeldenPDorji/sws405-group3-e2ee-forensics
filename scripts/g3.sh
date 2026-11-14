#!/usr/bin/env bash
# SWS405 Group 3 lab helper. Run from Terminal (macOS) or Git Bash (Windows) inside the g3-lab folder:
#   bash scripts/g3.sh <command> [args]
#
#   env                         lab setup summary (host, emulator, root, apps, tools)
#   mark <ID>                   log the time you just did a scripted action (logs/activity_log.csv)
#   stop-apps                   force-stop WhatsApp, Telegram, Signal; show airplane mode
#   fs <ID>                     file-system acquisition: tar of app data + notification history
#   adb-backup <ID>             logical acquisition: adb backup (confirm on the emulator screen)
#   app-backups <WA_ID|-> <SIG_ID|->   pull newest WhatsApp crypt15 and Signal .backup
#   decrypt-wa <ID> <FS_ID>     decrypt WhatsApp backup <ID> with the key from acquisition <FS_ID>
#   decrypt-signal <ID> <30-digit passphrase>
#
# Every acquisition is hashed (logs/hash_log.csv). Details go to logs/acquisition.log.
set -uo pipefail
export MSYS_NO_PATHCONV=1            # stop Git Bash rewriting /data/... into C:/Program Files/Git/data/...
cd "$(dirname "$0")/.." || exit 1
mkdir -p evidence work logs outputs tools

if [[ -x .venv/bin/python ]]; then PY=(.venv/bin/python)
elif [[ -x .venv/Scripts/python.exe ]]; then PY=(.venv/Scripts/python.exe)
elif command -v python3.12 >/dev/null 2>&1; then PY=(python3.12)
elif command -v py >/dev/null 2>&1; then PY=(py -3)
else PY=(python3); fi
G3PY=("${PY[@]}" scripts/g3.py)
LOG=logs/acquisition.log
PKGS=(com.whatsapp org.telegram.messenger org.thoughtcrime.securesms)
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

ver() { devsh dumpsys package "$1" | grep -m1 versionName | sed 's/.*versionName=//'; }

cmd_env() {
  need_root
  local tz; tz="$(devsh getprop persist.sys.timezone)"
  echo "== Group 3 lab setup =="
  echo "host / user : $(hostname) / $(whoami)"
  echo "host clock  : $(date '+%F %T %z')   (UTC $(date -u '+%T'))"
  echo "device clock: $(devsh date '+%F %T %z')   tz=$tz"
  echo "AVD         : $(adb emu avd name 2>/dev/null | tr -d '\r' | head -1) | $(devsh getprop ro.product.name) | Android $(devsh getprop ro.build.version.release) (API $(devsh getprop ro.build.version.sdk))"
  echo "build/root  : $(devsh getprop ro.build.type) $(devsh getprop ro.build.tags) | adb uid=$(devsh id -u) | airplane=$(devsh settings get global airplane_mode_on)"
  echo "WhatsApp    : $(ver com.whatsapp)"
  echo "Telegram    : $(ver org.telegram.messenger)"
  echo "Signal      : $(ver org.thoughtcrime.securesms)"
  echo "adb         : $(adb version | sed -n 2p | sed 's/Version //')"
  echo "Python      : $("${PY[@]}" --version 2>&1 | cut -d' ' -f2)   git: $(git --version | cut -d' ' -f3)"
  echo "ALEAPP      : $("${PY[@]}" tools/ALEAPP/aleapp.py --version 2>/dev/null | tail -1)"
  echo "wa-crypt    : $("${PY[@]}" -m pip show wa-crypt-tools 2>/dev/null | sed -n 's/^Version: //p')"
  echo "sbt         : $("$SIGTOOL" --help 2>&1 | grep -m1 -o 'version [0-9.]*')"
  local plist="/Applications/DB Browser for SQLite.app/Contents/Info.plist"
  if [[ -f "$plist" ]]; then
    echo "DB Browser  : $(defaults read "${plist%.plist}" CFBundleShortVersionString 2>/dev/null)"
    echo "OS          : macOS $(sw_vers -productVersion) $(uname -m)"
  fi
  log "env checked"
}

cmd_mark() {
  local id="${1:?usage: mark <ID>}" f=logs/activity_log.csv
  [[ -f $f ]] || echo "id,host_time_utc+06:00,host_time_utc,device_time" > "$f"
  local now     # Bhutan = UTC+06:00, no daylight saving
  now="$("${PY[@]}" -c "from datetime import datetime,timezone,timedelta;print(datetime.now(timezone(timedelta(hours=6))).strftime('%Y-%m-%d %H:%M:%S'))")"
  echo "$id,$now,$(date -u '+%F %T'),$(devsh date '+%F %T %z')" >> "$f"
  echo "marked $id at $now (UTC+06:00)"
}

cmd_stop() {
  for p in "${PKGS[@]}"; do adb shell am force-stop "$p"; done
  echo "apps stopped | airplane_mode_on=$(devsh settings get global airplane_mode_on)"
  log "apps force-stopped"
}

cmd_fs() {
  local id="${1:?usage: fs <ID>}"
  need_root
  local tarf="evidence/${id}_fs.tar" hashes="evidence/${id}_device_hashes.txt" out="work/$id"
  [[ -e $tarf ]] && { echo "ERROR: $tarf exists; pick a new ID"; exit 1; }
  : > "$hashes"
  for f in /data/data/com.whatsapp/databases/msgstore.db \
           /data/data/org.telegram.messenger/files/cache4.db \
           /data/data/org.thoughtcrime.securesms/databases/signal.db; do
    local h; h="$(devsh sha256sum "$f" | cut -d' ' -f1)"
    [[ -n "$h" ]] && echo "$h  $f  $out$f" >> "$hashes"
  done
  local want=(data/data/com.whatsapp data/data/org.telegram.messenger data/data/org.thoughtcrime.securesms
              data/media/0/Android/media/com.whatsapp data/media/0/Android/data/org.telegram.messenger
              data/media/0/Download data/media/0/Pictures data/system_ce/0/notification_history
              data/data/com.android.providers.contacts data/misc/keystore)
  local have=()
  for p in "${want[@]}"; do [[ "$(devsh "[ -e /$p ] && echo y")" == y ]] && have+=("$p"); done
  log "$id: tar of ${have[*]}"
  adb exec-out "tar -cf - -C / ${have[*]} 2>/dev/null" > "$tarf"
  mkdir -p "$out"
  tar -xf "$tarf" -C "$out" >> "$LOG" 2>&1 || log "$id: some entries could not be extracted on this host (see above)"
  "${G3PY[@]}" hash-add "$tarf" "$id" "file-system tar"
  echo "  device hashes taken: $(( $(wc -l < "$hashes") )) databases   extracted to $out/"
}

cmd_adb_backup() {
  local id="${1:?usage: adb-backup <ID>}"
  local abf="evidence/${id}_adb.ab"
  echo "Unlock the emulator and tap 'Back up my data' (leave the password empty)."
  adb backup -all -f "$abf" >> "$LOG" 2>&1
  "${G3PY[@]}" hash-add "$abf" "$id" "adb backup"
  "${G3PY[@]}" ab2tar "$abf" "work/$id"
}

pull_hashed() {   # pull_hashed <device path> <evidence file> <ID> <note>
  local h; h="$(devsh sha256sum "$1" | cut -d' ' -f1)"
  echo "$h  $1  $2" > "evidence/${3}_device_hashes.txt"
  adb pull -a "$1" "$2" >> "$LOG" 2>&1
  "${G3PY[@]}" hash-add "$2" "$3" "$4"
}

cmd_app_backups() {
  local wa="${1:?usage: app-backups <WA_ID|-> <SIG_ID|->}" sig="${2:?}"
  need_root
  if [[ $wa != - ]]; then
    local d=/sdcard/Android/media/com.whatsapp/WhatsApp/Databases
    local f; f="$(devsh "ls -t $d/msgstore.db.crypt* 2>/dev/null | head -1")"
    if [[ -n $f ]]; then pull_hashed "$f" "evidence/${wa}_${f##*/}" "$wa" "WhatsApp local backup"
    else echo "  $wa: no WhatsApp backup found in $d (record this as a finding)"; fi
  fi
  if [[ $sig != - ]]; then
    local f; f="$(devsh "ls -t /sdcard/Download/signal-*.backup 2>/dev/null | head -1")"
    if [[ -n $f ]]; then pull_hashed "$f" "evidence/${sig}_signal.backup" "$sig" "Signal on-device backup ${f##*/}"
    else echo "  $sig: no signal-*.backup in /sdcard/Download (check the folder chosen in Signal)"; fi
  fi
}

cmd_decrypt_wa() {
  local id="${1:?usage: decrypt-wa <ID> <FS_ID>}" fsid="${2:?}"
  local enc; enc="$(ls evidence/${id}_msgstore.db.crypt* 2>/dev/null | head -1)"
  [[ -n $enc ]] || { echo "ERROR: no evidence/${id}_msgstore.db.crypt*"; exit 1; }
  mkdir -p "work/$id"
  for k in "work/$fsid/data/data/com.whatsapp/files/encrypted_backup.key" "work/$fsid/data/data/com.whatsapp/files/key"; do
    [[ -f $k ]] || continue
    if "${PY[@]}" -m wa_crypt_tools.wadecrypt "$k" "$enc" "work/$id/msgstore.db" >> "$LOG" 2>&1 && [[ -s work/$id/msgstore.db ]]; then
      echo "  $id: decrypted with ${k#work/$fsid} -> work/$id/msgstore.db ($("${G3PY[@]}" sqlite-check "work/$id/msgstore.db"))"
      log "$id decrypted with $k"; return
    fi
  done
  echo "  $id: decryption failed with every key file found (details in $LOG)"
}

cmd_decrypt_signal() {
  local id="${1:?usage: decrypt-signal <ID> <passphrase>}"; shift
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
  env)            cmd_env ;;
  mark)           shift; cmd_mark "$@" ;;
  stop-apps)      cmd_stop ;;
  fs)             shift; cmd_fs "$@" ;;
  adb-backup)     shift; cmd_adb_backup "$@" ;;
  app-backups)    shift; cmd_app_backups "$@" ;;
  decrypt-wa)     shift; cmd_decrypt_wa "$@" ;;
  decrypt-signal) shift; cmd_decrypt_signal "$@" ;;
  *) sed -n '2,13p' "$0"; exit 1 ;;
esac
