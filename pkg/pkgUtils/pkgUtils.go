package pkgUtils

import "net/netip"

func IpToUint32(ip netip.Addr) uint32 {
	if !ip.Is4() {
		panic("Only IPv4 addresses are supported for this conversion")
	}
	ipBytes := ip.As4()
	return uint32(ipBytes[0])<<24 | uint32(ipBytes[1])<<16 | uint32(ipBytes[2])<<8 | uint32(ipBytes[3])
}

func Uint32ToIP(ipUint32 uint32) netip.Addr {
	ipBytes := []byte{
		byte(ipUint32 >> 24),
		byte((ipUint32 >> 16) & 0xFF),
		byte((ipUint32 >> 8) & 0xFF),
		byte(ipUint32 & 0xFF),
	}
	ip, ok := netip.AddrFromSlice(ipBytes)
	if !ok {
		panic("Failed to convert uint32 to netip.Addr")
	}
	return ip
}