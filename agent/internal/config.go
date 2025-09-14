package internal

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	ConfDir  = "/etc/zecx-hpot"
)

func confDir() string {
	if v := os.Getenv("ZECX_CONF_DIR"); v != "" {
		return v
	}
	return ConfDir
}

func confFile() string {
	return filepath.Join(confDir(), "agent.conf")
}

// ConfFile provides the resolved config file path for backward compatibility
// with older code that referenced internal.ConfFile as a string constant.
// It is evaluated at import time and honors ZECX_CONF_DIR if set.
var ConfFile = confFile()

func EnsureConfDir() error {
	return os.MkdirAll(confDir(), 0755)
}

func SaveAgentUUID(id string) error {
	if err := EnsureConfDir(); err != nil { return err }
	f, err := os.Create(confFile())
	if err != nil { return err }
	defer f.Close()
	_, err = fmt.Fprintf(f, "agent_uuid=%s\n", id)
	return err
}

func LoadAgentUUID() (string, error) {
	f, err := os.Open(confFile())
	if err != nil { return "", err }
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "agent_uuid=") {
			return strings.TrimPrefix(line, "agent_uuid="), nil
		}
	}
	return "", fmt.Errorf("agent_uuid not found in %s", filepath.Base(confFile()))
}
