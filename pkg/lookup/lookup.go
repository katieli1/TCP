package lookup

import (
	"errors"
	"fmt"
	"github.com/google/netstack/tcpip/header"
	"io"
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
	LookupTable LookupTable // Lookup table for neighbors
	Name        string
}

type Neighbor struct {
	IpPrefix      netip.Prefix
	UdpConn       net.Conn
	DestAddr      netip.Addr
	UDPAddr       netip.AddrPort
	InterfaceName string
}

type LookupTable map[netip.Addr]*Neighbor

// InterfaceTable now maps netip.Prefix to Interface
var InterfaceTable = make(map[netip.Prefix]*Interface)
var StaticRoutes map[netip.Prefix]netip.Addr

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage:  %s <configFile>\n", os.Args[0])
		os.Exit(1)
	}
	fileName := os.Args[1]
	populateTable(fileName)

	// for each entry point:
	// go readConn

}

func readConn(entryPoint *Neighbor) {
	for {
		headerBytes := make([]byte, ipv4header.HeaderLen)
		io.ReadFull(entryPoint.UdpConn, headerBytes)

		header, err := ipv4header.ParseHeader(headerBytes)
		if err != nil {
			// TODO: Handle error
		}

		dataBytes := make([]byte, header.TotalLen-header.Len)
		io.ReadFull(entryPoint.UdpConn, dataBytes)
		SendIP(header.Dst, 0, header, dataBytes)
	}
}

func populateTable(fileName string) {
	lnxConfig, err := lnxconfig.ParseConfig(fileName)
	if err != nil {
		panic(err)
	}
	StaticRoutes = lnxConfig.StaticRoutes
	for _, iface := range lnxConfig.Interfaces {
		prefixForm := netip.PrefixFrom(iface.AssignedIP, iface.AssignedPrefix.Bits())
		i := &Interface{
			Name:        iface.Name,
			IpPrefix:    prefixForm,
			IpAddr:      prefixForm.Addr(),
			UdpAddrPort: iface.UDPAddr,
			LookupTable: make(LookupTable), // Initialize empty LookupTable for this Interface
		}
		InterfaceTable[prefixForm] = i
	}
	for _, neighbor := range lnxConfig.Neighbor {
		// Find the matching Interface by its IpPrefix in InterfaceTable
		for prefix, iface := range InterfaceTable {
			if iface.Name == neighbor.InterfaceName {
				// If names match, create a Neighbor struct
				n := &Neighbor{
					IpPrefix:      netip.PrefixFrom(neighbor.DestAddr, prefix.Bits()), 
					DestAddr:      neighbor.DestAddr,
					UDPAddr:       neighbor.UDPAddr,
					InterfaceName: neighbor.InterfaceName,
				}
				// Add Neighbor to the Interface's LookupTable using the destination IP as the key
				iface.LookupTable[neighbor.DestAddr] = n
				createUdpConn(n)
				break
			}
		}
	}
}

func createUdpConn(neighbor *Neighbor) {
	addrPort := neighbor.UDPAddr
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
	neighbor.UdpConn = conn
}

func SendIP(dest netip.Addr, protocolNum int, header *ipv4header.IPv4Header, data []byte) error {
	//1. Validate the packet: check TTL and checksum
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

	message := data[headerSize:]
	for _, iface := range InterfaceTable {
		if dest == iface.IpAddr {
			// handle case where we reach a destination
		}
		if neighbor, exists := iface.LookupTable[dest]; exists {
			neighbor.UdpConn.Write(message)
			return nil
		}
	}
	for prefix := range StaticRoutes{
		//if prefix matches then
		SendIP(StaticRoutes[prefix],protocolNum,header,data)
	}
	return nil
}

func ValidateChecksum(b []byte, fromHeader uint16) uint16 {
	return header.Checksum(b, fromHeader)
}
