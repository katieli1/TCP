package lookup

import (
	"errors"
	"fmt"
	"github.com/google/netstack/tcpip/header"
	"ip/pkg/header-parser"
	"ip/pkg/lnxconfig"
	"net/netip"
	"os"
)

// type Interface struct {
// 	IpPrefix netip.Prefix
// 	IpAddr   netip.Addr
// 	UdpConn  netip.AddrPort
// 	Name     string
// }

var interfaces []lnxconfig.InterfaceConfig
var lookupTable = make(map[netip.Addr]*lnxconfig.InterfaceConfig)

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
		//i := &lnxconfig.InterfaceConfig{Name: iface.Name, IpPrefix: prefixForm, IpAddr: prefixForm.Addr(), UdpConn: iface.UDPAddr}
		lookupTable[prefixForm.Addr()] = &iface
		interfaces = lnxConfig.Interfaces
	}

}

func sendIP(dest netip.Addr, protocolNum int, data []byte) error {
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
	for i := range len(interfaces) {
		if dest == interfaces[i].AssignedIP {
			// yay
		}
	}
	fmt.Println(message) // so Go doesn't kill us

	// 3. if match for local network in forwarding table send to that network. if match for next hop IP, consult table again, and see if you have local match for that IP

	// 4. if no match anywhere, drop the packet and return an error
	return nil
}

func ValidateChecksum(b []byte, fromHeader uint16) uint16 {
	checksum := header.Checksum(b, fromHeader)

	return checksum
}
