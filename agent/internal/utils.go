package internal

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"github.com/google/uuid"
)

// GenerateUUID creates a new UUID.
func GenerateUUID() string {
	return uuid.New().String()
}

// GetSystemInfo gathers information about the system.
func GetSystemInfo() (string, error) {
	info := fmt.Sprintf("OS: %s, Architecture: %s", runtime.GOOS, runtime.GOARCH)
	return info, nil
}

// PairingCode generates a pairing code for the honeypot.
func PairingCode() string {
	return GenerateUUID()[:8] // Shortened for simplicity
}

// ExecuteCommand runs a shell command and returns the output.
func ExecuteCommand(command string) (string, error) {
	cmd := exec.Command("bash", "-c", command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// FirestoreConnectionString returns the connection string for Firestore.
func FirestoreConnectionString() string {
	return os.Getenv("FIRESTORE_CONNECTION_STRING")
}