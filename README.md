# SWS405 Group 3 lab: Signal artefacts on a rooted Android emulator

Run everything from Terminal (zsh) inside this folder (`cd ~/g3-lab`).

```
activity_script.csv   the 13 scripted Signal actions (type each text exactly; token first)
scripts/g3.sh         acquisition: env, mark, stop-app, fs, adb-backup, signal-backup, decrypt
scripts/g3.py         analysis: storage, score, disappear, verify (each fits one terminal screen)
evidence/             exhibits E01-E05 + device hash files   (large files are git-ignored)
work/                 extracted / decrypted copies (analysis only ever reads copies of these)
logs/                 hash_log.csv, activity_log.csv, acquisition.log   (commit these)
outputs/              ALEAPP report and run logs
tools/                ALEAPP clone                                    (git-ignored)
```

| ID  | What | When |
| --- | --- | --- |
| E01 | adb backup (logical) | right after the activity |
| E02 | file-system tar (root pull) | right after the activity, within 1 hour of S10 |
| E03 | Signal on-device backup, decrypted with its passphrase | right after the activity |
| E04 | file-system tar | more than 1 hour after S10 was read |
| E05 | Signal on-device backup | more than 1 hour after S10 was read |

Scope: WhatsApp and Telegram were left out because no test phone numbers were available,
and the brief allows test accounts only.
