package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	sshlib "github.com/gliderlabs/ssh"
    gossh "golang.org/x/crypto/ssh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

type Honeypot struct {
	B         Backend
	AgentUUID string
	sshSrv    *sshlib.Server
	httpSrv   *http.Server
	// dynamic generic services keyed as kind:port
	svcCancels map[string]context.CancelFunc
}

func NewHoneypot(b Backend, agentUUID string) *Honeypot {
	return &Honeypot{B: b, AgentUUID: agentUUID, svcCancels: map[string]context.CancelFunc{}}
}

// StartSSHListener starts a permissive SSH server capturing credentials and commands.
func (h *Honeypot) StartSSHListener(ctx context.Context, port int) error {
	// Ensure persistent host key to avoid host key changed warnings
	signer, err := ensureHostKey("/etc/zecx-hpot/ssh_host_rsa_key")
	if err != nil {
		log.Printf("failed to ensure host key: %v", err)
	}
	srv := &sshlib.Server{
		Addr: ":" + strconv.Itoa(port),
		Banner: "Welcome to Ubuntu 22.04 LTS\n",
		PasswordHandler: func(ctx sshlib.Context, password string) bool {
			attackerIP := ctx.RemoteAddr().String()
			_ = h.B.AddEvent(ctx, h.AgentUUID, Event{
				Timestamp:  time.Now(),
				AttackerIP: parseIP(attackerIP),
				TargetPort: port,
				Geo:        GeoIP(parseIP(attackerIP)),
				Type:       "SSH_LOGIN_ATTEMPT",
				Payload: map[string]interface{}{
					"username": ctx.User(),
					"password": password,
				},
				Severity: "Medium",
			})
			return true // allow session
		},
		// Accept keyboard-interactive as well (common on Windows/OpenSSH)
		KeyboardInteractiveHandler: func(ctx sshlib.Context, challenger gossh.KeyboardInteractiveChallenge) bool {
			attackerIP := ctx.RemoteAddr().String()
			_ = h.B.AddEvent(ctx, h.AgentUUID, Event{
				Timestamp:  time.Now(),
				AttackerIP: parseIP(attackerIP),
				TargetPort: port,
				Geo:        GeoIP(parseIP(attackerIP)),
				Type:       "SSH_KBDINT_ATTEMPT",
				Payload: map[string]interface{}{
					"username": ctx.User(),
				},
				Severity: "Low",
			})
			// No actual prompts; permit to maximize session capture
			return true
		},
		// Accept any public key to avoid immediate disconnects; log the attempt.
		PublicKeyHandler: func(ctx sshlib.Context, key sshlib.PublicKey) bool {
			attackerIP := ctx.RemoteAddr().String()
			_ = h.B.AddEvent(ctx, h.AgentUUID, Event{
				Timestamp:  time.Now(),
				AttackerIP: parseIP(attackerIP),
				TargetPort: port,
				Geo:        GeoIP(parseIP(attackerIP)),
				Type:       "SSH_PUBKEY_ATTEMPT",
				Payload: map[string]interface{}{
					"username": ctx.User(),
					"keyType": key.Type(),
				},
				Severity: "Low",
			})
			return true
		},
		Handler: func(s sshlib.Session) {
			attackerIP := s.RemoteAddr().String()
			log.Printf("SSH session started from %s", parseIP(attackerIP))
			// PTY detection (Windows/OpenSSH conpty). Drain window-change events to avoid blocking.
			if _, winCh, ok := s.Pty(); ok {
				go func() { for range winCh { /* ignore */ } }()
			}

			io.WriteString(s, "Welcome to Ubuntu 22.04 LTS (GNU/Linux 5.15 x86_64)\r\n")
			io.WriteString(s, "\r\nType 'help' for commands.\r\n")

			// Simple interactive line editor with echo to support Windows terminals.
			var buf []rune
			user := s.User()
			cwd := "/home/" + user
			files := map[string]string{}
			history := []string{}
			prompt := func() { io.WriteString(s, "\r\n"+cwd+"$ ") }
			prompt()
			b := make([]byte, 1)
			for {
				n, err := s.Read(b)
				if err != nil || n == 0 { return }
				ch := b[0]
				switch ch {
				case '\r':
					// Ignore CR; wait for LF
					continue
				case '\n':
					// Execute the line
					cmd := strings.TrimSpace(string(buf))
					buf = buf[:0]
					if cmd == "exit" || cmd == "logout" { io.WriteString(s, "\r\nlogout\r\n"); return }
					if cmd == "help" {
						io.WriteString(s, "\r\nAvailable: help, exit, pwd, ls, whoami, id, uname -a, cd, cat, echo, touch, sudo, ps aux, ifconfig, ip a, netstat -tulnp, history, wget, curl\r\n")
					} else if cmd != "" {
						// history (simple)
						history = append(history, cmd)
						// Log command
						_ = h.B.AddEvent(s.Context(), h.AgentUUID, Event{
							Timestamp:  time.Now(),
							AttackerIP: parseIP(attackerIP),
							TargetPort: port,
							Geo:        GeoIP(parseIP(attackerIP)),
							Type:       "SSH_COMMAND",
							Payload: map[string]interface{}{
								"command": cmd,
							},
							Severity: "Low",
						})
						// Very small command shim for realism
						switch {
						case cmd == "pwd":
							io.WriteString(s, "\r\n"+cwd+"\r\n")
						case cmd == "whoami":
							io.WriteString(s, "\r\n"+user+"\r\n")
						case cmd == "id":
							io.WriteString(s, fmt.Sprintf("\r\nuid=1000(%s) gid=1000(%s) groups=1000(%s),4(adm),24(cdrom),27(sudo)\r\n", user, user, user))
						case strings.HasPrefix(cmd, "uname"):
							io.WriteString(s, "\r\nLinux ubuntu 5.15.0-75-generic #82-Ubuntu SMP x86_64 GNU/Linux\r\n")
						case cmd == "history":
							for i, hcmd := range history { io.WriteString(s, fmt.Sprintf("\r\n%4d  %s", i+1, hcmd)) }
							io.WriteString(s, "\r\n")
						case cmd == "sudo" || strings.HasPrefix(cmd, "sudo "):
							io.WriteString(s, fmt.Sprintf("\r\n%s is not in the sudoers file.  This incident will be reported.\r\n", user))
						case cmd == "ps" || strings.HasPrefix(cmd, "ps "):
							io.WriteString(s, "\r\nUSER       PID %%CPU %%MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\nroot         1  0.0  0.1 168840  9500 ?        Ss   08:12   0:02 /sbin/init\r\nroot       532  0.0  0.2  89200 16400 ?        Ss   08:12   0:01 /usr/sbin/sshd -D\r\nwww-data   742  0.0  0.3 256000 22000 ?        S    08:14   0:00 /usr/sbin/apache2 -k start\r\nredis      810  0.0  0.2  98000 15000 ?        Ssl  08:15   0:00 /usr/bin/redis-server *:6379\r\n")

						case strings.HasPrefix(cmd, "ifconfig"):
							io.WriteString(s, "\r\neth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n\tinet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\r\n\tether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)\r\nlo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\r\n\tinet 127.0.0.1  netmask 255.0.0.0\r\n")
						case strings.HasPrefix(cmd, "ip a") || strings.HasPrefix(cmd, "ip addr"):
							io.WriteString(s, "\r\n1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\r\n    inet 127.0.0.1/8 scope host lo\r\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\r\n    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0\r\n")
						case strings.HasPrefix(cmd, "netstat"):
							io.WriteString(s, "\r\nActive Internet connections (only servers)\r\nProto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\r\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      532/sshd\r\ntcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      742/apache2\r\ntcp        0      0 0.0.0.0:6379            0.0.0.0:*               LISTEN      810/redis-server\r\n")
						case cmd == "ls" || strings.HasPrefix(cmd, "ls "):
							// very small fake listing
							if cwd == "/" {
								io.WriteString(s, "\r\nbin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var\r\n")
							} else if strings.HasPrefix(cwd, "/etc") {
								io.WriteString(s, "\r\nhosts  passwd  shadow  os-release  ssh/\r\n")
							} else if strings.HasPrefix(cwd, "/var/www/html") {
								io.WriteString(s, "\r\nindex.php  config.php  admin/\r\n")
							} else {
								base := ".  ..  Documents  Downloads  .bashrc  .profile  .ssh  Desktop"
								// include any created files
								extra := ""
								for p := range files { if strings.HasPrefix(p, cwd+"/") { name := strings.TrimPrefix(p, cwd+"/"); if !strings.Contains(name, "/") { extra += "  "+name } } }
								io.WriteString(s, "\r\n"+base+extra+"\r\n")
							}
						case strings.HasPrefix(cmd, "echo ") && strings.Contains(cmd, ">"):
							parts := strings.SplitN(cmd, ">", 2)
							content := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(parts[0]), "echo"))
							path := strings.TrimSpace(parts[1])
							if !strings.HasPrefix(path, "/") { if cwd == "/" { path = "/"+path } else { path = cwd+"/"+path } }
							files[path] = strings.Trim(content, "'\"")
						case strings.HasPrefix(cmd, "touch "):
							fn := strings.TrimSpace(strings.TrimPrefix(cmd, "touch "))
							if fn != "" {
								p := fn; if !strings.HasPrefix(p, "/") { if cwd == "/" { p = "/"+p } else { p = cwd+"/"+p } }
								if _, ok := files[p]; !ok { files[p] = "" }
							}
						case strings.HasPrefix(cmd, "cd "):
							arg := strings.TrimSpace(strings.TrimPrefix(cmd, "cd "))
							switch arg {
							case "", "~":
								cwd = "/home/" + user
							case ".":
								// no-op
							case "..":
								if cwd != "/" {
									if i := strings.LastIndex(cwd, "/"); i > 0 { cwd = cwd[:i] } else { cwd = "/" }
								}
							default:
								if strings.HasPrefix(arg, "/") {
									cwd = arg
								} else {
									if cwd == "/" { cwd = "/" + arg } else { cwd = cwd + "/" + arg }
								}
							}
						case strings.HasPrefix(cmd, "cat "):
							arg := strings.TrimSpace(strings.TrimPrefix(cmd, "cat "))
							p := arg; if !strings.HasPrefix(p, "/") { if cwd == "/" { p = "/"+p } else { p = cwd+"/"+p } }
							// known canned files
							switch p {
							case "/etc/passwd":
								io.WriteString(s, "\r\nroot:x:0:0:root:/root:/bin/bash\r\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\r\n"+user+":x:1000:1000::/home/"+user+":/bin/bash\r\n")
							case "/etc/hosts":
								io.WriteString(s, "\r\n127.0.0.1\tlocalhost\r\n192.168.1.100\tubuntu\r\n")
							case "/etc/os-release":
								io.WriteString(s, "\r\nNAME=\"Ubuntu\"\r\nVERSION=\"22.04 LTS\"\r\n")
							case "/proc/cpuinfo":
								io.WriteString(s, "\r\nprocessor\t: 0\r\nmodel name\t: Intel(R) Xeon(R) CPU\r\n")
							default:
								if c, ok := files[p]; ok { io.WriteString(s, "\r\n"+c+"\r\n") } else { io.WriteString(s, "\r\ncat: "+arg+": No such file or directory\r\n") }
							}
						case strings.HasPrefix(cmd, "wget ") || strings.HasPrefix(cmd, "curl "):
							// extract URL
							f := func(s string) string { s = strings.TrimSpace(s); parts := strings.Split(s, " "); for _, t := range parts { if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") { return t } }; return "" }
							url := f(cmd)
							if url == "" { io.WriteString(s, "\r\nUnable to resolve host\r\n"); break }
							io.WriteString(s, "\r\nSaving to: 'index.html'\r\n\r\nindex.html                100%[===================>]    1.23K  --.-KB/s    in 0s\r\n\r\nSaved\r\n")
						default:
							// Fallback
							io.WriteString(s, "\r\nbash: "+cmd+": command not found\r\n")
						}
					} else {
						io.WriteString(s, "\r\n")
					}
					prompt()
				case 0x7f, 0x08: // Backspace / DEL
					if len(buf) > 0 {
						// remove last rune
						buf = buf[:len(buf)-1]
						// erase char visually: move back, space, move back
						io.WriteString(s, "\b \b")
					}
				default:
					// Basic printable range; ignore other control sequences
					if ch >= 0x20 && ch <= 0x7e { // ASCII printable
						buf = append(buf, rune(ch))
						// echo
						_, _ = s.Write([]byte{ch})
					}
				}
			}
		},
	}
	if signer != nil { srv.AddHostKey(signer) }
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	log.Printf("SSH honeypot listening on :%d", port)
	h.sshSrv = srv
	return srv.ListenAndServe()
}

// StartHTTPListener starts a simple admin-login themed HTTP server and logs requests.
func (h *Honeypot) StartHTTPListener(ctx context.Context, port int) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_ = r.ParseForm()
			attacker := r.RemoteAddr
			payload := map[string]interface{}{}
			for k, v := range r.Header { payload["header_"+k] = strings.Join(v, "; ") }
			for k, v := range r.Form { payload["form_"+k] = strings.Join(v, ",") }
			_ = h.B.AddEvent(r.Context(), h.AgentUUID, Event{
				Timestamp:  time.Now(),
				AttackerIP: parseIP(attacker),
				TargetPort: port,
				Geo:        GeoIP(parseIP(attacker)),
				Type:       "HTTP_FORM_SUBMISSION",
				Payload:    payload,
				Severity:   "Medium",
			})
		}
		w.Header().Set("Content-Type", "text/html")
		_ = adminTpl.Execute(w, nil)
	})
	srv := &http.Server{ Addr: ":" + strconv.Itoa(port), Handler: mux }
	go func() { <-ctx.Done(); _ = srv.Close() }()
	log.Printf("HTTP honeypot listening on :%d", port)
	h.httpSrv = srv
	return srv.ListenAndServe()
}

// StopSSH stops the SSH server if running.
func (h *Honeypot) StopSSH() {
	if h.sshSrv != nil {
		_ = h.sshSrv.Close()
	}
}

// StopHTTP stops the HTTP server if running.
func (h *Honeypot) StopHTTP() {
	if h.httpSrv != nil {
		_ = h.httpSrv.Close()
	}
}

// StartGenericService starts a simple TCP service that optionally writes a banner and logs line-based input.
// kind examples: "telnet","ftp","smtp","redis","memcached","mysql","rdp","vnc","mqtt" (logged generically).
func (h *Honeypot) StartGenericService(parent context.Context, kind, name string, port int, banner string) error {
	key := kind+":"+strconv.Itoa(port)
	// Stop existing if running
	if c, ok := h.svcCancels[key]; ok { c(); delete(h.svcCancels, key) }
	l, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil { return err }
	ctx, cancel := context.WithCancel(parent)
	h.svcCancels[key] = cancel
	log.Printf("%s service listening on :%d", strings.ToUpper(kind), port)
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				select { case <-ctx.Done(): return; default: }
				continue
			}
			go func(c net.Conn) {
				defer c.Close()
				remote := c.RemoteAddr().String()
				// Log connect event
				_ = h.B.AddEvent(parent, h.AgentUUID, Event{
					Timestamp: time.Now(),
					AttackerIP: parseIP(remote),
					TargetPort: port,
					Geo: GeoIP(parseIP(remote)),
					Type: "SERVICE_CONNECT",
					Payload: map[string]interface{}{"service": kind, "name": name},
					Severity: "Low",
				})
				if banner != "" { _, _ = io.WriteString(c, banner) }
				// line-based reader with sane limit
				buf := make([]byte, 0, 4096)
				tmp := make([]byte, 1)
				deadline := time.Now().Add(30 * time.Second)
				_ = c.SetDeadline(deadline)
				for {
					n, err := c.Read(tmp)
					if err != nil || n == 0 { break }
					b := tmp[0]
					if b == '\r' { continue }
					if b == '\n' {
						line := strings.TrimSpace(string(buf))
						buf = buf[:0]
						if line != "" {
							_ = h.B.AddEvent(parent, h.AgentUUID, Event{
								Timestamp: time.Now(),
								AttackerIP: parseIP(remote),
								TargetPort: port,
								Geo: GeoIP(parseIP(remote)),
								Type: "SERVICE_COMMAND",
								Payload: map[string]interface{}{"service": kind, "name": name, "command": line},
								Severity: "Low",
							})
							// Minimal fake responses for some protocols
							switch kind {
							case "ftp":
								_, _ = io.WriteString(c, "500 Unknown command\r\n")
							case "telnet":
								_, _ = io.WriteString(c, line+"\r\n")
							case "redis":
								_, _ = io.WriteString(c, "-ERR unknown command\r\n")
							case "smtp":
								_, _ = io.WriteString(c, "500 5.5.2 Error: bad syntax\r\n")
							default:
								_, _ = io.WriteString(c, "OK\r\n")
							}
						} else {
							_, _ = io.WriteString(c, "\r\n")
						}
						// extend deadline on activity
						_ = c.SetDeadline(time.Now().Add(60 * time.Second))
						continue
					}
					// backspace
					if b == 0x7f || b == 0x08 {
						if len(buf) > 0 { buf = buf[:len(buf)-1] }
						continue
					}
					if len(buf) < 1024 { buf = append(buf, b) }
				}
			}(conn)
		}
	}()
	return nil
}

// StopGenericService stops a generic service by kind:port key.
func (h *Honeypot) StopGenericService(kind string, port int) {
	key := kind+":"+strconv.Itoa(port)
	if c, ok := h.svcCancels[key]; ok { c(); delete(h.svcCancels, key) }
}

var adminTpl = template.Must(template.New("admin").Parse(`<!doctype html>
<html><head><title>Admin Login</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css">
</head>
<body class="min-h-screen flex items-center justify-center bg-gray-100">
<form method="post" class="bg-white p-6 rounded shadow w-96">
<h1 class="text-xl font-semibold mb-4">Admin Login</h1>
<label class="block mb-2 text-sm">Username</label>
<input class="border rounded w-full px-3 py-2 mb-4" name="username" />
<label class="block mb-2 text-sm">Password</label>
<input class="border rounded w-full px-3 py-2 mb-4" type="password" name="password" />
<button class="bg-blue-600 text-white px-4 py-2 rounded w-full">Sign in</button>
</form>
</body></html>`))

func parseIP(remote string) string {
	if i := strings.LastIndex(remote, ":"); i != -1 { return remote[:i] }
	return remote
}

// GeoIP resolves a public IP to rough geolocation using ip-api.com; best-effort.
func GeoIP(ip string) map[string]interface{} {
	if ip == "" { return nil }
	// Simple, best-effort fetch with short timeout; avoid blocking if offline.
	client := &http.Client{ Timeout: 2 * time.Second }
	req, _ := http.NewRequest(http.MethodGet, "http://ip-api.com/json/"+ip, nil)
	resp, err := client.Do(req)
	if err != nil { return nil }
	defer resp.Body.Close()
	type rT struct{ Country, City string; Lat, Lon float64 }
	var data struct{
		Country string  `json:"country"`
		City    string  `json:"city"`
		Lat     float64 `json:"lat"`
		Lon     float64 `json:"lon"`
	}
	b, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(b, &data)
	if data.Country == "" && data.City == "" { return nil }
	return map[string]interface{}{"country": data.Country, "city": data.City, "lat": data.Lat, "lon": data.Lon}
}

// StartHoneytokenWatcher monitors a single file for reads and logs a Critical event.
func (h *Honeypot) StartHoneytokenWatcher(ctx context.Context, path string) {
	// We use atime polling every 5s to detect reads; fsnotify doesn't signal reads.
	var last int64
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ts, err := Atime(path)
			if err != nil { continue }
			if last != 0 && ts > last {
				// Read detected
				_ = h.B.AddEvent(ctx, h.AgentUUID, Event{
					Timestamp:  time.Now(),
					AttackerIP: "",
					TargetPort: 0,
					Geo:        nil,
					Type:       "HONEYTOKEN_READ",
					Payload:    map[string]interface{}{"path": path},
					Severity:   "Critical",
				})
			}
			last = ts
		}
	}
}

// ensureHostKey loads or generates a persistent RSA private key for SSH host identification.
func ensureHostKey(path string) (gossh.Signer, error) {
	// Try to read existing
	if b, err := os.ReadFile(path); err == nil {
		if signer, err2 := gossh.ParsePrivateKey(b); err2 == nil { return signer, nil }
	}
	// Ensure directory
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil { return nil, err }
	// Generate new RSA key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil { return nil, err }
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(path, keyPEM, 0o600); err != nil { return nil, err }
	signer, err := gossh.ParsePrivateKey(keyPEM)
	if err != nil { return nil, err }
	return signer, nil
}