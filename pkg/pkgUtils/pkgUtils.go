package pkgUtils

import (
	"net/netip"
)

// type VListener struct {
// 	Port int16
// }

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

// func (v *VTCPConn) Unmarshal(data []byte) error {
// 	buf := bytes.NewReader(data)

// 	// Unmarshal SourceIp (16 bytes + 1 byte for metadata)
// 	var sourceIpBytes [16]byte
// 	if err := binary.Read(buf, binary.BigEndian, &sourceIpBytes); err != nil {
// 		return err
// 	}
// 	var sourceIpLen byte
// 	if err := binary.Read(buf, binary.BigEndian, &sourceIpLen); err != nil {
// 		return err
// 	}
// 	v.SourceIp = netip.AddrFrom16(sourceIpBytes).Unmap()

// 	// Unmarshal SourcePort
// 	if err := binary.Read(buf, binary.BigEndian, &v.SourcePort); err != nil {
// 		return err
// 	}

// 	// Unmarshal DestIp (16 bytes + 1 byte for metadata)
// 	var destIpBytes [16]byte
// 	if err := binary.Read(buf, binary.BigEndian, &destIpBytes); err != nil {
// 		return err
// 	}
// 	var destIpLen byte
// 	if err := binary.Read(buf, binary.BigEndian, &destIpLen); err != nil {
// 		return err
// 	}
// 	v.DestIp = netip.AddrFrom16(destIpBytes).Unmap()

// 	// Unmarshal DestPort
// 	if err := binary.Read(buf, binary.BigEndian, &v.DestPort); err != nil {
// 		return err
// 	}

// 	return nil

// }

// func Marshal(v VTCPConn) ([]byte, error) {
// 	buf := new(bytes.Buffer)

// 	// Marshal SourceIp as 16 bytes (IPv4-mapped in IPv6 form) and 1 byte for metadata
// 	sourceIpBytes := v.SourceIp.As16()
// 	if err := binary.Write(buf, binary.BigEndian, sourceIpBytes); err != nil {
// 		return nil, err
// 	}
// 	if err := binary.Write(buf, binary.BigEndian, byte(v.SourceIp.BitLen()/8)); err != nil {
// 		return nil, err
// 	}

// 	// Marshal SourcePort
// 	if err := binary.Write(buf, binary.BigEndian, v.SourcePort); err != nil {
// 		return nil, err
// 	}

// 	// Marshal DestIp as 16 bytes and 1 byte for metadata
// 	destIpBytes := v.DestIp.As16()
// 	if err := binary.Write(buf, binary.BigEndian, destIpBytes); err != nil {
// 		return nil, err
// 	}
// 	if err := binary.Write(buf, binary.BigEndian, byte(v.DestIp.BitLen()/8)); err != nil {
// 		return nil, err
// 	}

// 	// Marshal DestPort
// 	if err := binary.Write(buf, binary.BigEndian, v.DestPort); err != nil {
// 		return nil, err
// 	}

// 	return buf.Bytes(), nil
// }
