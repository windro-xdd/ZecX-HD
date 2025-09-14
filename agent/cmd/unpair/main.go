package main

import (
    "context"
    "log"
    "os"
    "time"

    in "zecx-hpot/agent/internal"
    "cloud.google.com/go/firestore"
)

func main() {
    ctx := context.Background()

    proj := os.Getenv("FIREBASE_PROJECT_ID")
    if proj == "" { log.Fatal("FIREBASE_PROJECT_ID is required") }

    agentUUID, err := in.LoadAgentUUID()
    if err != nil || agentUUID == "" {
        log.Fatalf("failed loading agent uuid from %s: %v", in.ConfFile, err)
    }

    fs, err := in.NewFirestore(ctx, proj)
    if err != nil { log.Fatalf("firestore: %v", err) }
    defer fs.Close()

    // Clear pairing state and remove ownership
    doc := fs.Client.Collection("honeypots").Doc(agentUUID)
    _, err = doc.Update(ctx, []firestore.Update{
        {Path: "isPaired", Value: false},
        {Path: "ownerUid", Value: firestore.Delete},
        {Path: "pairingCode", Value: nil},
        {Path: "pairingExpiresAt", Value: time.Now().Add(-time.Hour)},
        {Path: "pairingRevokedAt", Value: time.Now()},
        {Path: "revokedReason", Value: "uninstall"},
    })
    if err != nil { log.Fatalf("unpair update failed: %v", err) }

    log.Printf("agent %s unpaired and pairing code revoked", agentUUID)
}
