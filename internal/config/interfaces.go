package config

import (
	"fmt"
	"net"
	"os"
)

// InterfaceOption describes a candidate capture NIC.
type InterfaceOption struct {
	Name  string
	Flags net.Flags
}

// ListCaptureInterfaces returns real, non-loopback network interfaces suitable
// for use as the capture interface, filtering out virtual/loopback devices.
func ListCaptureInterfaces() ([]InterfaceOption, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}

	var out []InterfaceOption
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if _, err := os.Stat("/sys/class/net/" + iface.Name); err != nil {
			continue // not a real device node
		}
		out = append(out, InterfaceOption{Name: iface.Name, Flags: iface.Flags})
	}
	return out, nil
}
