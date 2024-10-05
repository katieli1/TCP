package lookup

import (
	"errors"
	"fmt"
	"github.com/google/netstack/tcpip/header"
	"ip/pkg/header-parser"
	"ip/pkg/lnxconfig"
	"net"
	"net/netip"
	"os"
)

type Interface struct {
	IpPrefix    netip.Prefix
	IpAddr      netip.Addr
	UdpAddrPort netip.AddrPort
	UdpConn     net.Conn
	Name        string
}

var lookupTable = make(map[netip.Addr]*Interface)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage:  %s <configFile>\n", os.Args[0])
		os.Exit(1)
	}
	fileName := os.Args[1]
	populateTable(fileName)
}

func populateTable(fileName string) {

	// Parse the file
	lnxConfig, err := lnxconfig.ParseConfig(fileName)
	if err != nil {
		panic(err)
	}

	// Populate lookup table
	for _, iface := range lnxConfig.Interfaces {
		prefixForm := netip.PrefixFrom(iface.AssignedIP, iface.AssignedPrefix.Bits())
		i := &Interface{Name: iface.Name, IpPrefix: prefixForm, IpAddr: prefixForm.Addr(), UdpAddrPort: iface.UDPAddr}
		lookupTable[prefixForm.Addr()] = i
		createUdpConn(i)
	}

}

func createUdpConn(iface *Interface) {
	addrPort := iface.UdpAddrPort
	udpAddr := &net.UDPAddr{
		IP:   addrPort.Addr().AsSlice(), // Convert netip.Addr to net.IP
		Port: int(addrPort.Port()),      // Get the port from AddrPort
	}

	// Create a UDP connection (for sending)
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		fmt.Println("Error dialing UDP connection:", err)
		return
	}
	iface.UdpConn = conn
}

func SendIP(dest netip.Addr, protocolNum int, data []byte) error {
	//1. is the packet valid? is checksum and TTL 0? if no, drop
	header, err := ipv4header.ParseHeader(data)
	if err != nil {
		return err
	}
	if header.TTL == 0 {
		return errors.New("TTL expired")
	}
	headerSize := header.Len
	headerBytes := data[:headerSize]
	checksumFromHeader := uint16(header.Checksum)
	computedChecksum := ValidateChecksum(headerBytes, checksumFromHeader)

	if computedChecksum != checksumFromHeader {
		return errors.New("checksum is bad")
	}

	// 2. is the packet for me (based on dest address)? If it’s one of “your” IPs, send up to OS
	message := data[headerSize:]
	iface, exists := lookupTable[dest]
	if exists {
		iface.UdpConn.Write(message)
	} else { // 4. if no match anywhere, drop the packet and return an error
		return errors.New("destination IP is not known")
	}

	return nil
}

func ValidateChecksum(b []byte, fromHeader uint16) uint16 {
	checksum := header.Checksum(b, fromHeader)
	return checksum
}
