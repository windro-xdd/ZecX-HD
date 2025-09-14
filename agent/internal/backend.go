package internal

import (
    "context"
)

// Backend abstracts Firestore vs HTTP ingest backends.
type Backend interface {
    AddEvent(ctx context.Context, agentUUID string, ev Event) error
    AddTraffic(ctx context.Context, agentUUID string, t Traffic) error
    UpdateSystemInfo(ctx context.Context, agentUUID string, sysInfo SystemInfo) error
    SetStatus(ctx context.Context, agentUUID string, st Status) error
    UpdateLastSeen(ctx context.Context, agentUUID string) error
    GetSettings(ctx context.Context, agentUUID string) (Settings, bool, error)
    SeedPairing(ctx context.Context, agentUUID, pairingCode string, sysInfo SystemInfo) error
}
