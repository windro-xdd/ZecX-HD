package internal

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "time"
)

type HTTPIngest struct {
    BaseURL string
    Token   string // bearer token provisioned during pairing
    Client  *http.Client
}

func NewHTTPIngest(baseURL, token string) *HTTPIngest {
    if baseURL == "" { baseURL = "http://127.0.0.1:5000" }
    return &HTTPIngest{BaseURL: baseURL, Token: token, Client: &http.Client{Timeout: 10 * time.Second}}
}

func (h *HTTPIngest) do(ctx context.Context, method, path string, body any) error {
    var r io.Reader
    if body != nil {
        b, _ := json.Marshal(body)
        r = bytes.NewReader(b)
    }
    req, err := http.NewRequestWithContext(ctx, method, h.BaseURL+path, r)
    if err != nil { return err }
    if body != nil { req.Header.Set("Content-Type", "application/json") }
    if h.Token != "" { req.Header.Set("Authorization", "Bearer "+h.Token) }
    resp, err := h.Client.Do(req)
    if err != nil { return err }
    defer resp.Body.Close()
    if resp.StatusCode >= 300 {
        b, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("ingest %s %s: %s: %s", method, path, resp.Status, string(b))
    }
    return nil
}

func (h *HTTPIngest) AddEvent(ctx context.Context, agentUUID string, ev Event) error {
    return h.do(ctx, http.MethodPost, "/ingest/event", map[string]any{"agent_uuid": agentUUID, "event": ev})
}

func (h *HTTPIngest) AddTraffic(ctx context.Context, agentUUID string, t Traffic) error {
    return h.do(ctx, http.MethodPost, "/ingest/traffic", map[string]any{"agent_uuid": agentUUID, "traffic": t})
}

func (h *HTTPIngest) UpdateSystemInfo(ctx context.Context, agentUUID string, sysInfo SystemInfo) error {
    return h.do(ctx, http.MethodPost, "/ingest/system", map[string]any{"agent_uuid": agentUUID, "system": sysInfo})
}

func (h *HTTPIngest) SetStatus(ctx context.Context, agentUUID string, st Status) error {
    return h.do(ctx, http.MethodPost, "/ingest/status", map[string]any{"agent_uuid": agentUUID, "status": st})
}

func (h *HTTPIngest) UpdateLastSeen(ctx context.Context, agentUUID string) error {
    return h.do(ctx, http.MethodPost, "/ingest/heartbeat", map[string]any{"agent_uuid": agentUUID, "ts": time.Now()})
}

func (h *HTTPIngest) GetSettings(ctx context.Context, agentUUID string) (Settings, bool, error) {
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.BaseURL+"/ingest/settings?agent="+agentUUID, nil)
    if err != nil { return Settings{}, false, err }
    if h.Token != "" { req.Header.Set("Authorization", "Bearer "+h.Token) }
    resp, err := h.Client.Do(req)
    if err != nil { return Settings{}, false, err }
    defer resp.Body.Close()
    if resp.StatusCode == 404 { return Settings{}, false, nil }
    if resp.StatusCode >= 300 { b, _ := io.ReadAll(resp.Body); return Settings{}, false, fmt.Errorf("settings %s", string(b)) }
    var out struct{ Settings Settings `json:"settings"` }
    if err := json.NewDecoder(resp.Body).Decode(&out); err != nil { return Settings{}, false, err }
    return out.Settings, true, nil
}

func (h *HTTPIngest) SeedPairing(ctx context.Context, agentUUID, pairingCode string, sysInfo SystemInfo) error {
    return h.do(ctx, http.MethodPost, "/ingest/seed", map[string]any{
        "agent_uuid": agentUUID,
        "pairing_code": pairingCode,
        "system": sysInfo,
    })
}
