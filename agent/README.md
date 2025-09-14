# ZecX-HPot Agent

A stealthy honeypot agent that pairs with the dashboard and streams events/traffic to Firestore.

## Requirements
- Linux
- Go 1.22+
- A Firebase project and a service account JSON

## First run
1. Put your serviceAccountKey.json in this folder or later at `/etc/zecx-hpot/serviceAccountKey.json`.
2. Set environment `FIREBASE_PROJECT_ID` to your Firebase project ID.
3. Run installer:

```bash
chmod +x install.sh
sudo ./install.sh
```

It prints a pairing code once; enter it in the dashboard.

## Ports
- SSH honeypot: 22 (override `ZECX_SSH_PORT`)
- HTTP honeypot: 80 (override `ZECX_HTTP_PORT`)

The installer gives the binary the cap to bind low ports.
