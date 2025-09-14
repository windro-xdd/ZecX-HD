package internal

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

func GetHostname() string {
	name, _ := os.Hostname()
	return name
}

func GetOSVersion() string {
	// Try /etc/os-release
	f, err := os.Open("/etc/os-release")
	if err == nil {
		defer f.Close()
		s := bufio.NewScanner(f)
		for s.Scan() {
			line := s.Text()
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				return strings.Trim(line[len("PRETTY_NAME="):], "\"")
			}
		}
	}
	return runtime.GOOS + " " + runtime.GOARCH
}

func GetPrimaryIP() string {
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if (iface.Flags & net.FlagUp) == 0 { continue }
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() { continue }
			ip = ip.To4()
			if ip == nil { continue }
			return ip.String()
		}
	}
	return ""
}

func GetPrimaryMAC() string {
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if (iface.Flags & net.FlagLoopback) != 0 || (iface.Flags & net.FlagUp) == 0 { continue }
		if hw := iface.HardwareAddr.String(); hw != "" { return hw }
	}
	return ""
}

func Atime(path string) (int64, error) {
	// Use stat via shell for portability of atime
	out, err := exec.Command("stat", "-c", "%X", path).CombinedOutput()
	if err != nil { return 0, err }
	s := strings.TrimSpace(string(out))
	var ts int64
	_, err = fmt.Sscanf(s, "%d", &ts)
	return ts, err
}

// GetPublicIP queries a lightweight external service to determine the public IP.
// Returns empty string on failure.
func GetPublicIP() string {
	// Try a list of lightweight endpoints. Return first valid IP.
	endpoints := []string{
		"https://api.ipify.org?format=text",
		"https://checkip.amazonaws.com",
		"https://icanhazip.com",
		"https://ident.me",
		"http://ifconfig.me/ip",
	}
	for _, url := range endpoints {
		client := &http.Client{ Timeout: 2 * time.Second }
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		resp, err := client.Do(req)
		if err != nil || resp == nil { continue }
		if resp.StatusCode != 200 { resp.Body.Close(); continue }
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		ip := strings.TrimSpace(string(b))
		// Some services return trailing newline; trim again and validate
		if ip == "" { continue }
		if parsed := net.ParseIP(ip); parsed != nil {
			return ip
		}
		// Some services might return text with extra info; try last token
		fields := strings.Fields(ip)
		if len(fields) > 0 {
			if parsed := net.ParseIP(fields[len(fields)-1]); parsed != nil {
				return parsed.String()
			}
		}
	}
	return ""
}
