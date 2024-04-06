package log

import (
	"net"
	"strings"
)

func MaskIPAddress(ipStr string) string {
	if ipStr == "" {
		return ""
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}

	if ipv4 := ip.To4(); ipv4 != nil {
		mask := net.CIDRMask(24, 32) // 255.255.255.0
		maskedIP := ipv4.Mask(mask)
		return maskedIP.String()
	}

	mask := net.CIDRMask(48, 128) // ffff:ffff:ffff::
	maskedIP := ip.Mask(mask)
	return maskedIP.String()
}

func MaskEmail(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return ""
	}

	if len(parts[0]) > 5 {
		return parts[0][:2] + "*@" + parts[1]
	}

	if len(parts[0]) > 2 {
		return parts[0][:1] + "*@" + parts[1]
	}

	return "*@" + parts[1]
}
