# SWS405 Group 3: Signal artefacts on a rooted Android emulator

Group 3: Tshewang Dorji, Tandin Zangmo, Sonam Dorji Ghalley (leader), Kelden Phuntsho Dorji, Pema Dolker.

Run everything from Terminal (zsh) inside this folder (`cd ~/g3-lab`).

```
activity_script.csv   the scripted Signal actions (S1-S15; token first in every message)
scripts/g3.sh         acquisition: env, mark, stop-app, fs, adb-backup, signal-backup, decrypt
scripts/g3.py         analysis: storage, score, disappear, verify (each fits one terminal screen)
evidence/             exhibits + device-side hash files   (large exhibits are git-ignored)
logs/                 hash_log.csv, activity_log.csv, acquisition.log
outputs/              adb screen captures (E06, E07) and the ALEAPP run log
```

| ID  | What | Acquired (UTC+06:00) |
| --- | --- | --- |
| E01 | adb backup (logical): 0 Signal files | 2026-11-15 20:43:12 |
| E02 | file-system tar (root pull), before expiry | 2026-11-15 20:42:24 |
| E03 | Signal on-device backup (Backup V2 folder), before expiry; not decryptable with signalbackup-tools | 2026-11-15 20:42:28 |
| E04 | file-system tar, after the 1-hour timer expired | 2026-11-15 21:55:01 |
| E05 | Signal on-device backup, after expiry | 2026-11-15 21:55:06 |
| E06 | adb screen capture (home screen, taken by mistake, kept for continuity) | 2026-11-15 21:59:26 |
| E07 | adb screen capture of the Signal chat after expiry | 2026-11-15 22:01:53 |

All SHA-256 values are in `logs/hash_log.csv`. Final verification at 22:06:26: 7/7 exhibits and 10/10 device hashes MATCH.

Script notes: S10 was sent just before the timer was switched on and is the control; S14 is the disappearing message; S15 was added to time a notification.

Scope: WhatsApp and Telegram were left out because no extra test phone numbers were available, and the brief allows test accounts only.
