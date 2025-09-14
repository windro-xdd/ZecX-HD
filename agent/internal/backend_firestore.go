package internal

import (
    "context"
    "time"
)

// FirestoreBackend adapts Firestore client to the Backend interface.
type FirestoreBackend struct{ F *Firestore }

func NewFirestoreBackend(f *Firestore) *FirestoreBackend { return &FirestoreBackend{F: f} }

func (b *FirestoreBackend) AddEvent(ctx context.Context, agentUUID string, ev Event) error {
    return b.F.AddEvent(ctx, agentUUID, ev)
}

func (b *FirestoreBackend) AddTraffic(ctx context.Context, agentUUID string, t Traffic) error {
    return b.F.AddTraffic(ctx, agentUUID, t)
}

func (b *FirestoreBackend) UpdateSystemInfo(ctx context.Context, agentUUID string, sysInfo SystemInfo) error {
    return b.F.UpdateSystemInfo(ctx, agentUUID, sysInfo)
}

func (b *FirestoreBackend) SetStatus(ctx context.Context, agentUUID string, st Status) error {
    return b.F.SetStatus(ctx, agentUUID, st)
}

func (b *FirestoreBackend) UpdateLastSeen(ctx context.Context, agentUUID string) error {
    return b.F.UpdateLastSeen(ctx, agentUUID)
}

func (b *FirestoreBackend) GetSettings(ctx context.Context, agentUUID string) (Settings, bool, error) {
    return b.F.GetSettings(ctx, agentUUID)
}

func (b *FirestoreBackend) SeedPairing(ctx context.Context, agentUUID, pairingCode string, sysInfo SystemInfo) error {
    // Ensure doc and set pairingExpiresAt ~10 minutes from now
    if err := b.F.EnsureHoneypotDoc(ctx, agentUUID, pairingCode, sysInfo); err != nil { return err }
    if err := b.F.SetPairingExpiry(ctx, agentUUID, time.Now().Add(10*time.Minute)); err != nil { return err }
    return nil
}
