package lookup

import (
	"fmt"
	"ip/pkg/lnxconfig"
	"net/netip"
	"os"
)

type Interface struct {
	ipAddr  netip.Prefix
	udpConn netip.AddrPort
	name    string
}

var lookupTable = make(map[netip.Prefix]*Interface)

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
		i := &Interface{name: iface.Name, ipAddr: prefixForm, udpConn: iface.UDPAddr}
		lookupTable[prefixForm] = i
	}

}
