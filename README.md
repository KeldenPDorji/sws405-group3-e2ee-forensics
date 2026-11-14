# SWS405 Group 3 lab: WhatsApp, Telegram and Signal artefacts on Android

Run everything from Terminal (zsh) inside this folder (`cd ~/g3-lab`).

```
activity_script.csv   the 30 scripted actions (type each message exactly; token first)
scripts/g3.sh         acquisition: env, mark, stop-apps, fs, adb-backup, app-backups, decrypt-*
scripts/g3.py         analysis: storage, score, disappear, verify (each fits one terminal screen)
evidence/             exhibits E01-E06 + device hash files   (large files are git-ignored)
work/                 extracted / decrypted copies (analysis only ever reads copies of these)
logs/                 hash_log.csv, activity_log.csv, acquisition.log   (commit these)
outputs/              ALEAPP report and run logs
tools/                ALEAPP clone                                     (git-ignored)
```

Exhibits

| ID  | What | When |
| --- | --- | --- |
| E01 | adb backup (logical) | right after the activity |
| E02 | file-system tar (root pull) | right after the activity, within 1 hour of T10/S10 |
| E03 | WhatsApp local backup (crypt15), decrypted with the key from E02 | right after the activity |
| E04 | Signal on-device backup, decrypted with its passphrase | right after the activity |
| E05 | file-system tar | at least 24 h after W10 |
| E06 | Signal on-device backup | at least 24 h after W10 |

Exhibit files over 100 MB cannot go to GitHub: keep them on the group's shared drive and commit
`logs/hash_log.csv`, which proves their contents.
