package internal

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"cloud.google.com/go/firestore"
	"google.golang.org/api/option"
)

type Firestore struct {
	Client *firestore.Client
	ProjID string
}

func NewFirestore(ctx context.Context, projectID string) (*Firestore, error) {
	// Prefer explicit env if provided
	if env := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); env != "" {
		client, err := firestore.NewClient(ctx, projectID, option.WithCredentialsFile(env))
		if err == nil {
			return &Firestore{Client: client, ProjID: projectID}, nil
		}
		// If env failed, continue to try system path below
	}
	credsPath := "/etc/zecx-hpot/serviceAccountKey.json"
	// If system path exists and is readable, use it; otherwise error with guidance
	if fi, err := os.Stat(credsPath); err == nil && !fi.IsDir() {
		client, err := firestore.NewClient(ctx, projectID, option.WithCredentialsFile(credsPath))
		if err == nil { return &Firestore{Client: client, ProjID: projectID}, nil }
		// If permission denied or parse error, surface it but hint at env override
		return nil, fmt.Errorf("failed to create Firestore client using %s (try setting GOOGLE_APPLICATION_CREDENTIALS): %w", credsPath, err)
	}
	// Neither env nor system path available
	if env := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); env != "" {
		client, err := firestore.NewClient(ctx, projectID, option.WithCredentialsFile(env))
		if err == nil { return &Firestore{Client: client, ProjID: projectID}, nil }
		return nil, fmt.Errorf("failed to create Firestore client with GOOGLE_APPLICATION_CREDENTIALS: %w", err)
	}
	return nil, fmt.Errorf("service account credentials not found: set GOOGLE_APPLICATION_CREDENTIALS or place key at %s", credsPath)
}

func (f *Firestore) Close() {
	_ = f.Client.Close()
}

type SystemInfo struct {
	Hostname   string `firestore:"hostname"`
	OS         string `firestore:"os"`
	IPAddress  string `firestore:"ipAddress"`
	MACAddress string `firestore:"macAddress"`
	PublicIP   string `firestore:"publicIp"`
}

type Event struct {
	Timestamp  time.Time              `firestore:"timestamp"`
	AttackerIP string                 `firestore:"attackerIp"`
	TargetPort int                    `firestore:"targetPort"`
	Geo        map[string]interface{} `firestore:"geolocation"`
	Type       string                 `firestore:"type"`
	Payload    map[string]interface{} `firestore:"payload"`
	Severity   string                 `firestore:"severity"`
}

type Traffic struct {
	Timestamp time.Time `firestore:"timestamp"`
	BytesIn   int64     `firestore:"bytesIn"`
	BytesOut  int64     `firestore:"bytesOut"`
}

// Settings controls which listeners run and on what ports.
type Settings struct {
	EnableSSH  bool `firestore:"enableSSH"`
	EnableHTTP bool `firestore:"enableHTTP"`
	SSHPort    int  `firestore:"sshPort"`
	HTTPPort   int  `firestore:"httpPort"`
	Services   []Service `firestore:"services"`
}

// Service is a generic honeypot service configuration.
type Service struct {
	Name    string `firestore:"name"`
	Kind    string `firestore:"kind"` // e.g., "telnet","ftp","mysql","rdp","smb","redis","memcached","mqtt","vnc","http"
	Port    int    `firestore:"port"`
	Enabled bool   `firestore:"enabled"`
	Banner  string `firestore:"banner"`
}

// Status surfaces runtime state so the dashboard can show listening/error.
type Status struct {
	SSH       StatusEntry     `firestore:"ssh"`
	HTTP      StatusEntry     `firestore:"http"`
	Services  []ServiceStatus `firestore:"services"`
	UpdatedAt time.Time       `firestore:"updatedAt"`
}

type StatusEntry struct {
	Enabled   bool   `firestore:"enabled"`
	Port      int    `firestore:"port"`
	Listening bool   `firestore:"listening"`
	Error     string `firestore:"error"`
}

type ServiceStatus struct {
	Name      string `firestore:"name"`
	Kind      string `firestore:"kind"`
	Port      int    `firestore:"port"`
	Enabled   bool   `firestore:"enabled"`
	Listening bool   `firestore:"listening"`
	Error     string `firestore:"error"`
}

func (f *Firestore) EnsureHoneypotDoc(ctx context.Context, agentUUID, pairingCode string, sysInfo SystemInfo) error {
	doc := f.Client.Collection("honeypots").Doc(agentUUID)
	// Provide default settings if not present
	def := Settings{EnableSSH: true, EnableHTTP: true, SSHPort: 22, HTTPPort: 80, Services: []Service{}}
	_, err := doc.Set(ctx, map[string]interface{}{
		"agent_uuid": agentUUID,
		"pairingCode": pairingCode,
		"isPaired":   false,
		"systemInfo": sysInfo,
		"lastSeen":   time.Now(),
		"settings":   def,
	}, firestore.MergeAll)
	return err
}

func (f *Firestore) UpdatePairing(ctx context.Context, agentUUID string) error {
	doc := f.Client.Collection("honeypots").Doc(agentUUID)
	_, err := doc.Update(ctx, []firestore.Update{{Path: "pairingCode", Value: nil}, {Path: "isPaired", Value: true}})
	return err
}

func (f *Firestore) UpdateLastSeen(ctx context.Context, agentUUID string) error {
	// May fail under strict security rules; ignore errors
	_, err := f.Client.Collection("honeypots").Doc(agentUUID).Update(ctx, []firestore.Update{{Path: "lastSeen", Value: time.Now()}})
	if err != nil {
		log.Printf("lastSeen update failed (likely due to rules): %v", err)
	}
	return err
}

func (f *Firestore) AddEvent(ctx context.Context, agentUUID string, ev Event) error {
	_, _, err := f.Client.Collection("honeypots").Doc(agentUUID).Collection("events").Add(ctx, ev)
	return err
}

func (f *Firestore) AddTraffic(ctx context.Context, agentUUID string, t Traffic) error {
	_, _, err := f.Client.Collection("honeypots").Doc(agentUUID).Collection("traffic").Add(ctx, t)
	return err
}

// UpdateSystemInfo merges the latest system info into the honeypot document.
func (f *Firestore) UpdateSystemInfo(ctx context.Context, agentUUID string, sysInfo SystemInfo) error {
	_, err := f.Client.Collection("honeypots").Doc(agentUUID).Set(ctx, map[string]interface{}{
		"systemInfo": sysInfo,
	}, firestore.MergeAll)
	return err
}

// SetSettings merges settings into the honeypot document.
func (f *Firestore) SetSettings(ctx context.Context, agentUUID string, s Settings) error {
	_, err := f.Client.Collection("honeypots").Doc(agentUUID).Set(ctx, map[string]interface{}{
		"settings": s,
	}, firestore.MergeAll)
	return err
}

// SetStatus writes runtime status (agent-side; dashboard reads only).
func (f *Firestore) SetStatus(ctx context.Context, agentUUID string, st Status) error {
	st.UpdatedAt = time.Now()
	_, err := f.Client.Collection("honeypots").Doc(agentUUID).Set(ctx, map[string]interface{}{
		"status": st,
	}, firestore.MergeAll)
	return err
}

// GetSettings fetches the current settings; returns ok=false if doc missing.
func (f *Firestore) GetSettings(ctx context.Context, agentUUID string) (Settings, bool, error) {
	doc := f.Client.Collection("honeypots").Doc(agentUUID)
	snap, err := doc.Get(ctx)
	if err != nil { return Settings{}, false, err }
	if !snap.Exists() { return Settings{}, false, nil }
	var s struct{ Settings Settings `firestore:"settings"` }
	if err := snap.DataTo(&s); err != nil { return Settings{}, true, err }
	return s.Settings, true, nil
}

// SetPairingExpiry updates the pairing expiration timestamp.
func (f *Firestore) SetPairingExpiry(ctx context.Context, agentUUID string, t time.Time) error {
	_, err := f.Client.Collection("honeypots").Doc(agentUUID).Set(ctx, map[string]any{
		"pairingExpiresAt": t,
	}, firestore.MergeAll)
	return err
}
