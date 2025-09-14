# ZecX-HPot (Trusted devices, Firestore-only)

A minimal honeypot agent you can install with a single command on machines you control. The agent writes to your Firebase Firestore project using a service account placed on the host.

Components:
- Go agent (systemd service) sending telemetry to Firestore
- Firestore rules to enforce pairing and safe updates

## Quick start

1) Firebase
- Create a Firebase project and enable Firestore (Native mode)
- Generate a service account key (JSON) and save it locally (do not commit)
- Optional: set your default project in `backend/.firebaserc`

2) Deploy Firestore rules
- From repo root:
	- Install Firebase CLI and login
	- Deploy rules with the included config

3) Agent install (target machine)
- Put your service account at `agent/serviceAccountKey.json`
- Run the installer:
	- With Go on target: `sudo ./install.sh`
	- Without Go (prebuilt): build once (`cd agent && CGO_ENABLED=0 go build -o network-dispatcher ./cmd && CGO_ENABLED=0 go build -o zecx-unpair ./cmd/unpair`), bundle the binaries in `agent/`, then run `sudo ./install.sh --use-prebuilt`

What the installer does:
- Installs the key to `/etc/zecx-hpot/serviceAccountKey.json` (0600)
- Auto-detects projectId from the key (or use `--project <id>`)
- Seeds once and prints a pairing code (also saved under `/etc/zecx-hpot`)
- Installs/starts `network-dispatcher.service`

## Uninstall
- Keep config: `sudo ./agent/uninstall.sh`
- Full purge: `sudo ./agent/uninstall.sh --purge`

## Repo hygiene
- Do not commit real credentials. `.gitignore` already excludes `serviceAccountKey.json` anywhere in the repo.

## Distribute and use freely

Yes—this repo is ready to push to GitHub. A few notes so users can safely use it out-of-the-box:

- Do not commit real credentials. We added a repo-level .gitignore to exclude any `serviceAccountKey.json` files and local artifacts. Include the provided `agent/serviceAccountKey.example.json` to show the expected format.
- Provide your own Firebase project. Users must create a Firebase project and generate their own service account JSON. The agent runs with the Admin SDK and only uses Firestore.
- Uninstall auto-unpairs. Removing the agent via `agent/uninstall.sh` will revoke ownership (ownerUid cleared, isPaired=false) and invalidate any existing pairing code.
- Pairing codes are time-limited and revoked on uninstall. After uninstall, any previously printed code is invalid until a new one is generated on reinstall or via `agent/pair.sh`.

Optional: You can publish signed release binaries for Linux to make install easier without Go; the scripts already handle system integration via systemd.
