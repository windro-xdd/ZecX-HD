package main

import (
    "context"
    "crypto/rand"
    "fmt"
    "log"
    "math/big"
    "os"
    "time"

    in "zecx-hpot/agent/internal"
    gfirestore "cloud.google.com/go/firestore"
)

func main() {
    ctx := context.Background()

    proj := os.Getenv("FIREBASE_PROJECT_ID")
    if proj == "" {
        log.Fatal("FIREBASE_PROJECT_ID is required")
    }

    agentUUID, err := in.LoadAgentUUID()
    if err != nil || agentUUID == "" {
        log.Fatalf("failed loading agent uuid from %s: %v", in.ConfFile, err)
    }

    fs, err := in.NewFirestore(ctx, proj)
    if err != nil { log.Fatalf("firestore: %v", err) }
    defer fs.Close()

    code := pairingCode()
    expiresAt := time.Now().Add(10 * time.Minute)

    // Write pairingCode and mark not paired
    doc := fs.Client.Collection("honeypots").Doc(agentUUID)
    if _, err := doc.Set(ctx, map[string]interface{}{
        "pairingCode":       code,
        "pairingExpiresAt":  expiresAt,
        "isPaired":          false,
    }, gfirestore.MergeAll); err != nil {
        log.Fatalf("update pairing code failed: %v", err)
    }

    fmt.Println(code)
}

func pairingCode() string {
    // 12-char base32-like code grouped as XXXX-XXXX-XXXX (more entropy than 6 digits)
    const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // exclude ambiguous chars
    b := make([]byte, 12)
    for i := 0; i < 12; i++ {
        idx := randInt(0, len(alphabet))
        b[i] = alphabet[idx]
    }
    return fmt.Sprintf("%s-%s-%s", string(b[0:4]), string(b[4:8]), string(b[8:12]))
}

func randInt(min, max int) int {
    if max <= min { return min }
    x, err := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
    if err != nil { return min }
    return int(x.Int64()) + min
}
