// Package machineid derives the device identifier the protocol sends
// as `machineId` on every request.
//
// Algorithm (verified against captured traffic): the identifier is the
// first 32 hex chars of SHA-256 over the UTF-8 bytes of /etc/machine-id
// on Linux. This matches QSysInfo::machineUniqueId() reading that file,
// then QCryptographicHash::hash(..., Sha256) truncated to 32 hex chars.
package machineid

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// LinuxMachineID returns the derived protocol machineId.
func LinuxMachineID() (string, error) {
	raw, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		// Fall back to /var/lib/dbus/machine-id, the other canonical path.
		raw, err = os.ReadFile("/var/lib/dbus/machine-id")
		if err != nil {
			return "", fmt.Errorf("machineid: no machine id found: %w", err)
		}
	}
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return "", fmt.Errorf("machineid: empty machine id")
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:32], nil
}
