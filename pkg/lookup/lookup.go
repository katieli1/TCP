package lookup

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/google/netstack/tcpip/header"
	"ip/pkg/header-parser"
	"ip/pkg/lnxconfig"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
)

type NetworkEntry struct {
	IpPrefix    netip.Prefix
	IpAddr      netip.Addr
	UdpAddrPort netip.AddrPort
	LookupTable LookupTable // Lookup table for neighbors
	Name        string
	Up          bool
	IsInterface bool // True if this is an interface entry, false if it’s a route
}

type Neighbor struct {
	UdpConn       net.Conn
	DestAddr      netip.Addr
	UdpAddrPort   netip.AddrPort
	InterfaceName string
}

type LookupTable map[netip.Addr]*Neighbor

// Combined table for interfaces and static routes
var networkTable = make(map[netip.Prefix]*NetworkEntry)

type HandlerFunc func(string)

var handlerTable = make(map[uint8]HandlerFunc)

func Initialize(fileName string) {
	populateTable(fileName)

	for _, entry := range networkTable {
		if entry.IsInterface {
			udpAddr, err := net.ResolveUDPAddr("udp4", entry.UdpAddrPort.String())
			if err != nil {
				log.Panicln("Error resolving UDP address: ", err)
			}
			udpConn, err := net.ListenUDP("udp4", udpAddr)
			if err != nil {
				log.Panicln("Error setting up UDP listener: ", err)
			}
			for n := range entry.LookupTable {
				go readConn(entry.LookupTable[n], entry, udpConn)
			}
		}
	}

	done := make(chan struct{})
	go func() {
		REPL()
		close(done)
	}()

	<-done
}

func RegisterRecvHandler(protocolNum uint8, callbackFunc HandlerFunc) error {
	if protocolNum != 0 && protocolNum != 200 {
		return errors.New("Invalid protocolNum")
	}
	handlerTable[protocolNum] = callbackFunc
	return nil
}
func REPL() {
	fmt.Println("Welcome to the CLI! Valid commands include li, ln, lr, up <ifname>, down <ifname>, send <addr> <message ...>, and q to quit.")
	reader := bufio.NewReader(os.Stdin)
	for {
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		words := strings.Fields(input) // splits by space

		if input == "q" { // quit
			break
		} else if input == "li" { // list interfaces
			fmt.Println("Name    Addr/Prefix    State")
			for key := range networkTable {
				iface := networkTable[key]
				state := "Up"
				if !iface.Up {
					state = "Down"
				}
				fmt.Println(iface.Name + "     " + iface.IpPrefix.String() + "    " + state)
			}
		} else if input == "ln" { // list neighbors
			fmt.Println("Iface    VIP       UDPAddr")
			for key := range networkTable {
				iface := networkTable[key]
				if iface.Up { // don't print neighbors for ifaces that are down
					for neighborAddr := range iface.LookupTable {
						udpConn := iface.LookupTable[neighborAddr].UdpConn.RemoteAddr().String() // TODO: make sure remote addr (not local) is correct
						fmt.Println(iface.Name + "      " + neighborAddr.String() + "  " + udpConn)
					}
				}
			}
		} else if input == "lr" { // list routes
			fmt.Println("T       Prefix        Next hop   Cost")
			for key := range networkTable {
				iface := networkTable[key]
				if iface.Up { // don't print neighbors for ifaces that are down
					for neighborAddr := range iface.LookupTable { // ONLY DOES TYPE L
						neighbor := iface.LookupTable[neighborAddr]
						fmt.Println("L       " + iface.IpPrefix.String() + "   " + neighbor.InterfaceName + "        0")
					}

					// TODO: S and R, NEED TO TALK ABOUT HOW TO ABSTRACT STATICROUTES TO BE HOST-ONLY
				}
			}

		} else if words[0] == "up" {
			changeInterfaceState(true, words)

		} else if words[0] == "down" {
			changeInterfaceState(false, words)

		} else if words[0] == "send" {
			if len(words) != 3 {
				fmt.Println("Error: format of send command must be send <addr> <message ...>")
			} else {
				dest, err := netip.ParseAddr(words[1])
				if err != nil {
					fmt.Println("Error parsing IP address:", err)
					continue
				}

				var src netip.Addr
				for key := range networkTable {
					iface := networkTable[key]
					src = iface.IpAddr
					break
				}

				// need to create header
				header := &ipv4header.IPv4Header{Version: 4, Len: 20, TTL: 64, Dst: dest, Src: src, TotalLen: len(words[2]) + ipv4header.HeaderLen} // determining source is complicated
				headerBytes, err := header.Marshal()
				if err != nil {
					fmt.Println("Error marshaling header:", err)
					return
				}

				header.Checksum = int(ComputeChecksum(headerBytes))
				headerBytes, err = header.Marshal()
				if err != nil {
					fmt.Println("Error marshaling header after checksum:", err)
					return
				}

				payload := []byte(words[2])
				fmt.Printf("Marshalled header: %x\n", headerBytes) // Check header bytes
				fmt.Printf("Payload: %x\n", payload)               // Check payload bytes

				packet := append(headerBytes, payload...) // Append payload to header
				fmt.Printf("Data bytes: %v\n", packet)    // Print bytes as slice
				fmt.Printf("Data as string: %s\n", string(packet))
				SendIP(dest, 0, packet)
			}

		} else {
			fmt.Println("Invalid command. Valid commands include li, ln, lr, up <ifname>, down <ifname>, send <addr> <message ...>, and q to quit.")
		}
	}
}

func changeInterfaceState(up bool, words []string) {
	if len(words) != 2 {
		fmt.Println("Error: format of up command must be up <ifname>")
	} else {
		ifname := words[1]

		for key := range networkTable {
			if networkTable[key].Name == ifname {
				networkTable[key].Up = up
			}
		}
	}
}


func readConn(neighbor *Neighbor, iface *NetworkEntry, conn net.Conn) {
	for {
		fmt.Println("in readConn")
		if iface.Up {
			fmt.Println("iface.Up")

			// // Read the IPv4 header
			// headerBytes := make([]byte, ipv4header.HeaderLen)
			// if _, err := readFully(conn, headerBytes); err != nil {
			//     fmt.Println("Error reading header:", err)
			//     continue
			// }
			// fmt.Printf("Header bytes: %v\n", headerBytes)

			// header, err := ipv4header.ParseHeader(headerBytes)
			// if err != nil {
			//     fmt.Println("Error parsing header:", err)
			//     continue
			// }

			// // Set payload length based on header (e.g., 2 bytes or variable length)
			// payloadLen := 2 // Replace with dynamic length if protocol specifies it
			// dataBytes := make([]byte, payloadLen)

			// if _, err := readFully(conn, dataBytes); err != nil {
			//     fmt.Println("Error reading data:", err)
			//     continue
			// }
			// fmt.Printf("Data bytes: %v\n", dataBytes)
			// fmt.Printf("Data as string: %s\n", string(dataBytes))

			buf := make([]byte, 4096)
			_, err := conn.Read(buf)

			if err != nil {
				// TODO
			}

			header, err := ipv4header.ParseHeader(buf[:ipv4header.HeaderLen])
			if err != nil {
				fmt.Println("Error parsing header:", err)
				continue
			}

			SendIP(header.Dst, 0, buf)
		}
	}
}

// readFully reads exactly len(buf) bytes from conn into buf.
func readFully(conn net.Conn, buf []byte) (int, error) {
	totalRead := 0
	for totalRead < len(buf) {
		n, err := conn.Read(buf[totalRead:])
		if err != nil {
			return totalRead, err
		}
		totalRead += n
	}
	return totalRead, nil
}

func createUdpConn(neighbor *Neighbor) {
	addrPort := neighbor.UdpAddrPort
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
func SendIP(dest netip.Addr, protocolNum uint8, packet []byte) error {
	fmt.Println("in send IP")
	header, err := ipv4header.ParseHeader(packet[:ipv4header.HeaderLen])
	if err != nil {
		return err
	}
	
	if header.TTL == 0 {
		return errors.New("TTL expired")
	}

	headerSize := header.Len
	headerBytes := packet[:headerSize]
	checksumFromHeader := uint16(header.Checksum)
	computedChecksum := ValidateChecksum(headerBytes, checksumFromHeader)

	if computedChecksum != checksumFromHeader {
		return errors.New("checksum is bad")
	}

	message := packet[headerSize:]
	var bestMatch *NetworkEntry

	// Iterate through the networkTable to find the longest prefix match
	for prefix, entry := range networkTable {
		if prefix.Contains(dest) {
			if header.Dst == networkTable[prefix].IpAddr{
				callback := handlerTable[protocolNum]
				callback(string(message))
				return nil
			}
			if bestMatch == nil || prefix.Bits() > bestMatch.IpPrefix.Bits() {
				bestMatch = entry
			}
		}
	}

	if bestMatch != nil {
		fmt.Println("in best match")
		if bestMatch.IsInterface {
			if bestMatch.Up {
				if neighbor, exists := bestMatch.LookupTable[dest]; exists {
					neighbor.UdpConn.Write(packet)
					return nil
				}
			}
			return nil
		}
		SendIP(bestMatch.IpAddr, protocolNum, packet)
	}

	return errors.New("no valid route found")
}

// Populate the combined networkTable
func populateTable(fileName string) {
	lnxConfig, err := lnxconfig.ParseConfig(fileName)
	if err != nil {
		panic(err)
	}
	
	for _, iface := range lnxConfig.Interfaces {
		prefixForm := netip.PrefixFrom(iface.AssignedIP, iface.AssignedPrefix.Bits())
		entry := &NetworkEntry{
			Name:        iface.Name,
			IpPrefix:    prefixForm,
			IpAddr:      prefixForm.Addr(),
			UdpAddrPort: iface.UDPAddr,
			LookupTable: make(LookupTable),
			Up:          true,
			IsInterface: true,
		}
		networkTable[prefixForm] = entry
	}

	for _, neighbor := range lnxConfig.Neighbors {
		for _, entry := range networkTable {
			if entry.Name == neighbor.InterfaceName {
				n := &Neighbor{
					DestAddr:      neighbor.DestAddr,
					UdpAddrPort:   neighbor.UDPAddr,
					InterfaceName: neighbor.InterfaceName,
				}
				entry.LookupTable[neighbor.DestAddr] = n
				createUdpConn(n)
				break
			}
		}
	}

	for prefix, nextHop := range lnxConfig.StaticRoutes {
		networkTable[prefix] = &NetworkEntry{
			IpPrefix:    prefix,
			IpAddr:      nextHop, // Next hop for static route
			IsInterface: false,   // Not an interface, it's a static route
		}
	}
}

func ValidateChecksum(b []byte, fromHeader uint16) uint16 {
	return header.Checksum(b, fromHeader)
}

// Compute the checksum using the netstack package
func ComputeChecksum(b []byte) uint16 {
	checksum := header.Checksum(b, 0)

	// Invert the checksum value.  Why is this necessary?
	// This function returns the inverse of the checksum
	// on an initial computation.  While this may seem weird,
	// it makes it easier to use this same function
	// to validate the checksum on the receiving side.
	// See ValidateChecksum in the receiver file for details.
	checksumInv := checksum ^ 0xffff

	return checksumInv
}
