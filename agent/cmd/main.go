package main

import (
	"context"
	crand "crypto/rand"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	in "zecx-hpot/agent/internal"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Prefer HTTP ingest mode if configured
	ingestURL := os.Getenv("ZECX_INGEST_URL")
	ingestToken := os.Getenv("ZECX_INGEST_TOKEN")
	useIngest := ingestURL != "" || ingestToken != ""

	// Firestore project is only needed in direct mode
	projectID := os.Getenv("FIREBASE_PROJECT_ID")
	if !useIngest && projectID == "" {
		log.Fatal("FIREBASE_PROJECT_ID is required (or set ZECX_INGEST_URL/ZECX_INGEST_TOKEN for HTTP ingest)")
	}

	var (
		b  in.Backend
		fs *in.Firestore
	)

	// Load or create agent UUID
	agentUUID, err := in.LoadAgentUUID()
	if err != nil || agentUUID == "" {
		agentUUID = in.GenerateUUID()
		if err := in.SaveAgentUUID(agentUUID); err != nil {
			log.Fatalf("save agent uuid: %v", err)
		}
		// First-run: generate pairing code and seed backend
		code := pairingCode()
		sys := in.SystemInfo{
			Hostname:   in.GetHostname(),
			OS:         in.GetOSVersion(),
			IPAddress:  in.GetPrimaryIP(),
			MACAddress: in.GetPrimaryMAC(),
			PublicIP:   in.GetPublicIP(),
		}
		if useIngest {
			b = in.NewHTTPIngest(ingestURL, ingestToken)
			if err := b.SeedPairing(ctx, agentUUID, code, sys); err != nil {
				log.Printf("seed pairing (ingest) failed: %v", err)
			}
		} else {
			var ferr error
			fs, ferr = in.NewFirestore(ctx, projectID)
			if ferr != nil {
				log.Fatalf("firestore init: %v", ferr)
			}
			defer fs.Close()
			b = in.NewFirestoreBackend(fs)
			if err := b.SeedPairing(ctx, agentUUID, code, sys); err != nil {
				log.Fatalf("seed pairing (firestore): %v", err)
			}
		}
		fmt.Println(code) // print pairing code once on first run
	}

	// Initialize backend for normal run
	if b == nil {
		if useIngest {
			b = in.NewHTTPIngest(ingestURL, ingestToken)
		} else {
			var ferr error
			fs, ferr = in.NewFirestore(ctx, projectID)
			if ferr != nil {
				log.Fatalf("firestore: %v", ferr)
			}
			b = in.NewFirestoreBackend(fs)
		}
	}

	// Honeypot
	hp := in.NewHoneypot(b, agentUUID)

	// Defaults if settings missing
	sshPort := getEnvInt("ZECX_SSH_PORT", 22)
	httpPort := getEnvInt("ZECX_HTTP_PORT", 80)

	// Start defaults immediately
	go func() {
		if err := hp.StartSSHListener(ctx, sshPort); err != nil {
			log.Printf("SSH listener error on :%d: %v", sshPort, err)
			_ = b.SetStatus(ctx, agentUUID, in.Status{SSH: in.StatusEntry{Enabled: true, Port: sshPort, Listening: false, Error: err.Error()}})
		}
	}()
	go func() {
		if err := hp.StartHTTPListener(ctx, httpPort); err != nil {
			log.Printf("HTTP listener error on :%d: %v", httpPort, err)
			_ = b.SetStatus(ctx, agentUUID, in.Status{HTTP: in.StatusEntry{Enabled: true, Port: httpPort, Listening: false, Error: err.Error()}})
		}
	}()

	// Settings watcher (polling via backend)
	go func() {
		var lastSSH, lastHTTP bool = true, true
		var lastSPort, lastHPort int = sshPort, httpPort
		running := map[string]in.Service{}
		for {
			set, ok, err := b.GetSettings(ctx, agentUUID)
			if err != nil {
				time.Sleep(5 * time.Second)
				continue
			}
			curSSH := set.EnableSSH
			curHTTP := set.EnableHTTP
			curSPort := set.SSHPort
			curHPort := set.HTTPPort
			if !ok {
				curSSH, curHTTP = true, true
				curSPort, curHPort = sshPort, httpPort
			}
			if curSPort == 0 {
				curSPort = sshPort
			}
			if curHPort == 0 {
				curHPort = httpPort
			}

			if curSSH && (!lastSSH || curSPort != lastSPort) {
				hp.StopSSH()
				go func(p int) {
					if err := hp.StartSSHListener(ctx, p); err != nil {
						log.Printf("SSH listener error on :%d: %v", p, err)
						_ = b.SetStatus(ctx, agentUUID, in.Status{SSH: in.StatusEntry{Enabled: true, Port: p, Listening: false, Error: err.Error()}})
					} else {
						_ = b.SetStatus(ctx, agentUUID, in.Status{SSH: in.StatusEntry{Enabled: true, Port: p, Listening: true}})
					}
				}(curSPort)
			} else if !curSSH && lastSSH {
				hp.StopSSH()
				_ = b.SetStatus(ctx, agentUUID, in.Status{SSH: in.StatusEntry{Enabled: false, Port: curSPort, Listening: false}})
			}

			if curHTTP && (!lastHTTP || curHPort != lastHPort) {
				hp.StopHTTP()
				go func(p int) {
					if err := hp.StartHTTPListener(ctx, p); err != nil {
						log.Printf("HTTP listener error on :%d: %v", p, err)
						_ = b.SetStatus(ctx, agentUUID, in.Status{HTTP: in.StatusEntry{Enabled: true, Port: p, Listening: false, Error: err.Error()}})
					} else {
						_ = b.SetStatus(ctx, agentUUID, in.Status{HTTP: in.StatusEntry{Enabled: true, Port: p, Listening: true}})
					}
				}(curHPort)
			} else if !curHTTP && lastHTTP {
				hp.StopHTTP()
				_ = b.SetStatus(ctx, agentUUID, in.Status{HTTP: in.StatusEntry{Enabled: false, Port: curHPort, Listening: false}})
			}

			// Reconcile additional services
			desired := map[string]in.Service{}
			for _, svc := range set.Services {
				desired[svc.Kind+":"+strconv.Itoa(svc.Port)] = svc
			}
			for key, cur := range running {
				want, ok := desired[key]
				if !ok || !want.Enabled || want.Banner != cur.Banner || want.Name != cur.Name {
					hp.StopGenericService(cur.Kind, cur.Port)
					delete(running, key)
				}
			}
			for key, svc := range desired {
				if !svc.Enabled {
					continue
				}
				if _, ok := running[key]; ok {
					continue
				}
				banner := svc.Banner
				if banner == "" {
					switch svc.Kind {
					case "telnet":
						banner = "\r\nUbuntu 22.04 LTS\r\nlogin: "
					case "ftp":
						banner = "220 (vsFTPd 3.0.3)\r\n"
					case "smtp":
						banner = "220 mail ESMTP Postfix\r\n"
					case "mysql":
						banner = "\x05\x00\x00\x0a5.7.42\x00"
					case "memcached":
						banner = "\r\n"
					case "vnc":
						banner = "RFB 003.008\n"
					}
				}
				go func(svc in.Service, bnr string, key string) {
					if err := hp.StartGenericService(ctx, svc.Kind, svc.Name, svc.Port, bnr); err != nil {
						log.Printf("%s service error on :%d: %v", svc.Kind, svc.Port, err)
						_ = b.AddEvent(ctx, agentUUID, in.Event{Timestamp: time.Now(), Type: "SERVICE_START_ERROR", TargetPort: svc.Port, Payload: map[string]any{"service": svc.Kind, "name": svc.Name, "error": err.Error()}, Severity: "High"})
						_ = b.SetStatus(ctx, agentUUID, in.Status{Services: []in.ServiceStatus{{Name: svc.Name, Kind: svc.Kind, Port: svc.Port, Enabled: true, Listening: false, Error: err.Error()}}})
						return
					}
					running[key] = svc
					_ = b.SetStatus(ctx, agentUUID, in.Status{Services: []in.ServiceStatus{{Name: svc.Name, Kind: svc.Kind, Port: svc.Port, Enabled: true, Listening: true}}})
				}(svc, banner, key)
			}

			lastSSH, lastHTTP = curSSH, curHTTP
			lastSPort, lastHPort = curSPort, curHPort

			_ = b.UpdateSystemInfo(ctx, agentUUID, in.SystemInfo{Hostname: in.GetHostname(), OS: in.GetOSVersion(), IPAddress: in.GetPrimaryIP(), MACAddress: in.GetPrimaryMAC(), PublicIP: in.GetPublicIP()})
			time.Sleep(5 * time.Second)
		}
	}()

	// Push system info once
	pubIP := in.GetPublicIP()
	log.Printf("Resolved public IP: %s", pubIP)
	_ = b.UpdateSystemInfo(ctx, agentUUID, in.SystemInfo{Hostname: in.GetHostname(), OS: in.GetOSVersion(), IPAddress: in.GetPrimaryIP(), MACAddress: in.GetPrimaryMAC(), PublicIP: pubIP})

	// Honeytoken watcher
	go func() { hp.StartHoneytokenWatcher(ctx, "/var/www/html/config.php") }()

	// Traffic ticker
	go func() {
		var lastIn, lastOut int64
		for {
			time.Sleep(10 * time.Second)
			m, err := in.ReadProcTotals()
			if err != nil {
				continue
			}
			inTot, outTot := in.SumTotals(m)
			var dIn, dOut int64
			if lastIn != 0 {
				dIn = inTot - lastIn
			}
			if lastOut != 0 {
				dOut = outTot - lastOut
			}
			lastIn, lastOut = inTot, outTot
			_ = b.AddTraffic(ctx, agentUUID, in.Traffic{Timestamp: time.Now(), BytesIn: dIn, BytesOut: dOut})
		}
	}()

	// Heartbeat
	go func() {
		for {
			time.Sleep(60 * time.Second)
			_ = b.UpdateLastSeen(ctx, agentUUID)
			_ = b.UpdateSystemInfo(ctx, agentUUID, in.SystemInfo{Hostname: in.GetHostname(), OS: in.GetOSVersion(), IPAddress: in.GetPrimaryIP(), MACAddress: in.GetPrimaryMAC(), PublicIP: in.GetPublicIP()})
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	cancel()
	if fs != nil {
		fs.Close()
	}
}

// pairingCode returns AAAA-BBBB-CCCC format using A-Z and 0-9
func pairingCode() string {
	alphabet := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	pick := func(n int) string {
		b := make([]rune, n)
		for i := range b {
			idx, _ := crand.Int(crand.Reader, big.NewInt(int64(len(alphabet))))
			b[i] = alphabet[idx.Int64()]
		}
		return string(b)
	}
	return fmt.Sprintf("%s-%s-%s", pick(4), pick(4), pick(4))
}

func getEnvInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}