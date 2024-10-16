package lookup

import (
	"bufio"
	"errors"
	"fmt"
	ipv4header "ip/pkg/header-parser"
	"ip/pkg/lnxconfig"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/netstack/tcpip/header"
	"sync"
)

var networkTableLock sync.RWMutex

type NetworkEntry struct {
	IpPrefix     netip.Prefix
	IpAddr       netip.Addr
	UdpAddrPort  netip.AddrPort
	LookupTable  LookupTable // Lookup table for neighbors
	Name         string
	Up           bool
	IsDefault    bool
	Default      netip.Addr
	RipNeighbors []*Neighbor
}

type RouteInfo struct {
	Cost         int
	PrefixLength int
	Address      netip.Addr
}

type Neighbor struct {
	UdpConn       net.Conn
	DestAddr      netip.Addr
	UdpAddrPort   netip.AddrPort
	IpPrefix      netip.Prefix
	NextHop       netip.Addr
	InterfaceName string
	Cost          int
	WillHop       bool
	LastHeard     time.Time
	IsRouter      bool
}

type LookupTable map[netip.Addr]*Neighbor

// Combined table for interfaces and static routes
var networkTable = make(map[netip.Prefix][]*NetworkEntry)

type HandlerFunc func(string)

var handlerTable = make(map[uint8]HandlerFunc)

var isRouter bool

const maxPacketSize = 1400

var timeoutLimit time.Duration
var ripUpdateRate time.Duration

func Initialize(fileName string) {
	populateTable(fileName)
	networkTableLock.RLock()
	for _, listOfEntries := range networkTable {
		for i := range listOfEntries {
			entry := listOfEntries[i]
			if !entry.IsDefault {
				udpAddr, err := net.ResolveUDPAddr("udp4", entry.UdpAddrPort.String())
				if err != nil {
					log.Panicln("Error resolving UDP address: ", err)
				}
				udpConn, err := net.ListenUDP("udp4", udpAddr)
				if err != nil {
					log.Panicln("Error setting up UDP listener: ", err)
				}
				for range entry.LookupTable {
					go readConn(entry, udpConn)

				}

				if isRouter {
					// for prefix := range networkTable {
					// 	iface := networkTable[prefix]
					// 	if !iface.IsDefault {
					go sendRIPData(entry)
					// 	}
					// }
				}
			}
		}

	}
	networkTableLock.RUnlock()
	go checkNeighbors()

	// if isRouter {
	// 	go sendRIPData()
	// }
	done := make(chan struct{})
	go func() {
		REPL()
		close(done)
	}()

	<-done
}

func callback(message string, nextHop netip.Addr) {
	// fmt.Println("In Callback, message:", message)
	var routes []RouteInfo
	entries := strings.Split(message, ";")
	for _, entry := range entries {
		fields := strings.Split(entry, ",")
		if len(fields) != 3 {
			fmt.Println("Skipping malformed entry:", entry)
			continue
		}

		cost, err := strconv.Atoi(fields[0])
		if err != nil {
			fmt.Println("Invalid cost:", fields[0])
			continue
		}

		prefixLength, err := strconv.Atoi(fields[1])
		if err != nil {
			fmt.Println("Invalid prefix length:", fields[1])
			continue
		}

		addr, err := netip.ParseAddr(strings.TrimSpace(strings.ReplaceAll(fields[2], "\x00", "")))
		if err != nil {
			fmt.Println("Invalid address:", fields[2], "Error:", err)
			continue
		}
		//if it is one of my interfaces, don't add it
		routes = append(routes, RouteInfo{
			Cost:         cost,
			PrefixLength: prefixLength,
			Address:      addr,
		})
		// fmt.Println("Parsed route: address =", addr.String(), ", cost =", cost, ", prefix length =", prefixLength)
	}

	for _, route := range routes {
		prefix := netip.PrefixFrom(route.Address, route.PrefixLength)
		// fmt.Println("Processing route for prefix:", prefix.String())

		maskedPrefix := newPrefixFromAddr(prefix)
		fmt.Println("masked prefix returned by helper func: ", maskedPrefix)
		if entries, exists := networkTable[maskedPrefix]; exists {
			for i := range entries {
				if entries[i].Name != "" {
					continue
				}
				entry := entries[i]
				if neighbor, found := entry.LookupTable[route.Address]; found {
					//poison reverse - split horizon
					newCost = route.Cost + 1
					if newCost >= maxCost {
						// Mark route as unreachable by setting maxCost
						neighbor.Cost = maxCost
					} else if neighbor.NextHop == nextHop || neighbor.Cost > newCost {
						neighbor.Cost = newCost
						neighbor.NextHop = nextHop
					}
				} else {
					fmt.Println("Adding new neighbor:", route.Address.String())

					entry.LookupTable[route.Address] = &Neighbor{
						DestAddr: route.Address,
						Cost:     route.Cost + 1,
						IpPrefix: newPrefixFromAddr(prefix),
						NextHop:  nextHop,
						WillHop:  true,
					}
				}
				entry.LookupTable[route.Address].LastHeard = time.Now()
			}
		} else {
			newEntry := &NetworkEntry{
				IpPrefix:    newPrefixFromAddr(prefix),
				IpAddr:      nextHop,
				LookupTable: make(map[netip.Addr]*Neighbor),
				Up:          true,
				IsDefault:   false,
			}
			newEntry.LookupTable[route.Address] = &Neighbor{
				DestAddr:  route.Address,
				Cost:      route.Cost + 1,
				IpPrefix:  newPrefixFromAddr(prefix),
				NextHop:   nextHop,
				WillHop:   true,
				LastHeard: time.Now(),
			}
			maskedPrefix := newPrefixFromAddr(prefix)
			fmt.Println("masked prefix returned by helper func: ", maskedPrefix)
			networkTable[maskedPrefix] = append(networkTable[maskedPrefix], newEntry)
		}

	}

}

func sendRIPData(entry *NetworkEntry) {
	for {
		time.Sleep(ripUpdateRate)
		var messageBuilder strings.Builder

		networkTableLock.RLock()
		for _, listOfEntries := range networkTable {
			for i := range listOfEntries {
				entry := listOfEntries[i]
				if entry.IsDefault {
					continue
				}
				for _, neighbor := range entry.LookupTable {
					var cost int
					//split horizon
					if neighbor.NextHop == entry.IpAddr {
						// Poison reverse
						cost = infinity
					} else {
						cost = neighbor.Cost
					}

					message := fmt.Sprintf("%d,%d,%s;", cost, entry.IpPrefix.Bits(), neighbor.DestAddr.String())
					messageBuilder.WriteString(message)
					// fmt.Println("Appending to message:", message)
				}
			}
		}
		networkTableLock.RUnlock()

		message := strings.TrimSuffix(messageBuilder.String(), ";")
		if message == "" {
			fmt.Println("No routes to send.")
			continue
		}

		messageBytes := []byte(message)
		// fmt.Println("Constructed RIP message:", message)

		for _, neighbor := range entry.RipNeighbors {
			// fmt.Println("Sending to Rip Neighbor:", neighbor.DestAddr.String())
			header := &ipv4header.IPv4Header{
				Version:  4,
				Len:      20,
				TTL:      64,
				Dst:      neighbor.DestAddr,
				Src:      entry.IpAddr,
				TotalLen: len(message) + ipv4header.HeaderLen,
				Protocol: 200,
			}
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

			packet := append(headerBytes, messageBytes...)
			// fmt.Println("Sending packet to:", neighbor.DestAddr.String(), "Message:", message)
			SendIP(neighbor.DestAddr, 200, packet)
		}
	}
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

		words := strings.SplitN(input, " ", 3) // splits on the first 2 spaces

		if input == "q" { // quit
			break
		} else if input == "li" { // list interfaces
			fmt.Println("Name    Addr/Prefix    State")
			for _, ifaceList := range networkTable {
				for _, iface := range ifaceList {
					state := "Up"
					if !iface.Up {
						state = "Down"
					}
					fmt.Println(iface.Name + "     " + iface.IpPrefix.String() + "    " + state)
				}
			}

		} else if input == "ln" { // list neighbors
			fmt.Println("Iface    VIP       UDPAddr")
			for key := range networkTable {
				listOfEntries := networkTable[key]
				for i := range listOfEntries {
					iface := listOfEntries[i]
					if iface.Up { // don't print neighbors for ifaces that are down
						for neighborAddr := range iface.LookupTable {
							if iface.LookupTable[neighborAddr].NextHop == iface.LookupTable[neighborAddr].DestAddr {
								// udpConn := iface.LookupTable[neighborAddr].UdpConn.RemoteAddr().String() // TODO: make sure remote addr (not local) is correct
								// fmt.Println(iface.Name + "      " + neighborAddr.String() + "  " + udpConn)
							}

							// ONLY FOR DEBUGGING; DELETE FOR FINAL VERSION
							// nextHop := iface.LookupTable[neighborAddr].NextHop
							// fmt.Println(iface.Name + "      " + "Address " + neighborAddr.String() + " Prefix " + neighborAddr.String() + " Next hop " + nextHop.String())
						}
					}
				}

			}
		} else if input == "lr" { // list routes
			fmt.Println("T       Prefix        Next hop   Cost")
			for key := range networkTable {
				for i := range networkTable[key] {
					iface := networkTable[key][i]
					if iface.Up { // don't print neighbors for ifaces that are down
						var t string
						if !iface.IsDefault {
							t = "L       "
						} else {
							if isRouter {
								t = "R       "
							} else {
								t = "S       "
							}
						}
						for neighborAddr := range iface.LookupTable {
							neighbor := iface.LookupTable[neighborAddr]

							fmt.Println(t + iface.IpPrefix.String() + "   " + neighbor.InterfaceName + "        0")
						}

					}
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

				//TODO: fix
				var src netip.Addr
				// for key := range networkTable {
				// 	iface := networkTable[key]
				// 	src = iface.IpAddr
				// 	break
				// }

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
				// fmt.Printf("Marshalled header: %x\n", headerBytes) // Check header bytes
				// fmt.Printf("Payload: %x\n", payload)               // Check payload bytes

				packet := append(headerBytes, payload...) // Append payload to header
				// fmt.Printf("Data bytes: %v\n", packet)    // Print bytes as slice
				// fmt.Printf("Data as string: %s\n", string(packet))
				SendIP(dest, 0, packet)
			}

		} else {
			fmt.Println("Invalid command. Valid commands include li, ln, lr, up <ifname>, down <ifname>, send <addr> <message ...>, and q to quit.")
		}
	}
}

func changeInterfaceState(up bool, words []string) {
	if len(words) != 2 {
		if up {
			fmt.Println("Error: format of up command must be up <ifname>")
		} else {
			fmt.Println("Error: format of down command must be down <ifname>")
		}
	} else {
		ifname := words[1]

		for key := range networkTable {
			for i := range networkTable[key] {
				iface := networkTable[key][i]
				if iface.Name == ifname {
					iface.Up = up
				}
			}

		}
	}
}

func readConn(iface *NetworkEntry, conn net.Conn) {

	for {

		if iface.Up {
			buf := make([]byte, maxPacketSize)

			_, err := conn.Read(buf)

			if err != nil {
				// TODO
			}

			header, err := ipv4header.ParseHeader(buf[:ipv4header.HeaderLen])

			if err != nil {
				fmt.Println("Error parsing header:", err)
				continue
			}

			var protocol uint8 = 0
			if header.Protocol == 200 {
				protocol = 200
				// start stopwatch
				// message := buf[header.Len:]
				// entries := strings.Split(string(message), ";")
				// for _, entry := range entries {
				// 	fields := strings.Split(entry, ",")
				// 	if len(fields) != 3 {
				// 		fmt.Println("Skipping malformed entry:", entry)

				// 	}
				// 	addr, err := netip.ParseAddr(strings.TrimSpace(strings.ReplaceAll(fields[2], "\x00", "")))
				// 	if err != nil {
				// 		fmt.Println("Invalid address:", fields[2], "Error:", err)
				// 		continue
				// 	}

				// 	fmt.Println("received information about address " + addr.String())

				// 	n, exists := iface.LookupTable[addr]
				// 	fmt.Println("does the address exist? ", exists)
				// 	if exists {
				// 		fmt.Println("Updating LastHeard for " + addr.String())
				// 		n.LastHeard = time.Now()
				// 	}

				// }

			}
			SendIP(header.Dst, protocol, buf)
			fmt.Println("left sendIP")
		}
	}
}

func checkNeighbors() {
	// for key := range iface.LookupTable { // initialize times
	// 	iface.LookupTable[key].LastHeard = time.Now()
	// }
	for {
		//fmt.Println("in check neighbors loop")
		//time.Sleep(2 * time.Second)
		networkTableLock.Lock()

		for i := range networkTable {
			for n := range networkTable[i] {
				//for n := range l {
				iface := networkTable[i][n]

				if isRouter {
					for addr := range iface.LookupTable {

						lastHeard := iface.LookupTable[addr].LastHeard
						if !lastHeard.IsZero() {

							fmt.Println("time since I last heard from the router at " + addr.String() + " is " + time.Since(lastHeard).String())

							if time.Since(lastHeard) >= timeoutLimit {
								fmt.Println("Timeout exceeded")
								removeNeighbor(addr) // removes IP address from every NetworkEntry's LookupTable
								break                // exit loop to stop thread
							}
						}

					}

				}
			}
		}
		networkTableLock.Unlock()

	}
}

func removeNeighbor(ip netip.Addr) { // removes IP address from every NetworkEntry's LookupTable

	fmt.Println("in removeNeighbor")
	for n := range networkTable {
		for i := range networkTable[n] {
			neighbor, exists := networkTable[n][i].LookupTable[ip]

			if exists {
				if neighbor.UdpConn != nil {
					neighbor.UdpConn.Close()
				}

				newRipNeighbors := make([]*Neighbor, 0, len(networkTable[n][i].RipNeighbors))
				for _, nb := range networkTable[n][i].RipNeighbors {
					if neighbor.DestAddr != ip {
						newRipNeighbors = append(newRipNeighbors, nb) // Keep valid neighbors
					} else {
						fmt.Printf("Removing neighbor with IP: %s\n", ip)
					}
				}
				networkTable[n][i].RipNeighbors = newRipNeighbors
				delete(networkTable[n][i].LookupTable, ip) // remove this entry from the LookupTable

			}

		}
	}

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
	if protocolNum == 0 {
		fmt.Println("Start of SendIP function, Destination:", dest.String())
	}
	header, err := ipv4header.ParseHeader(packet[:ipv4header.HeaderLen])
	if err != nil {
		return fmt.Errorf("error parsing header: %w", err)
	}

	if header.TTL == 0 {
		return errors.New("TTL expired")
	}

	headerSize := header.Len
	headerBytes := packet[:headerSize]
	checksumFromHeader := uint16(header.Checksum)
	computedChecksum := ValidateChecksum(headerBytes, checksumFromHeader)

	if computedChecksum != checksumFromHeader {
		fmt.Println("Checksum mismatch: Expected:", checksumFromHeader, "Computed:", computedChecksum)
		return errors.New("checksum is bad")
	}

	message := packet[headerSize:]
	if protocolNum == 0 {
		fmt.Println("Message in SendIP:", string(message))
		fmt.Println("Destination Address:", dest.String())
	}

	var bestMatch netip.Prefix
	networkTableLock.RLock()
	for prefix := range networkTable {

		for i := range networkTable[prefix] {
			addr := networkTable[prefix][i].IpAddr
			if addr == header.Dst && networkTable[prefix][i].Name != "" {
				if protocolNum == 200 {
					// fmt.Println("Invoking callback with message:", string(message))
					callback(string(message), header.Src)
					networkTableLock.RUnlock()
					return nil
				}
				if callback, found := handlerTable[protocolNum]; found {
					fmt.Println("Invoking handler callback for protocol:", protocolNum)
					callback(string(message))
					networkTableLock.RUnlock()
					return nil
				}
			}
		}
		if protocolNum == 0 {
			fmt.Println("Possible best match: ", prefix.String())
		}

		if prefix.Contains(dest) && (bestMatch.Bits() == 0 || prefix.Bits() > bestMatch.Bits()) {
			bestMatch = newPrefixFromAddr(prefix)
			if protocolNum == 0 {
				fmt.Println("Updating best match to:", prefix.String())
			}
		}
	}
	networkTableLock.RUnlock()

	if bestMatch.IsValid() {
		if protocolNum == 0 {
			fmt.Println("Best match prefix found:", bestMatch.String())
		}
		for i := range networkTable[bestMatch] {
			e := networkTable[bestMatch][i]
			fmt.Println("length of networkTable[bestMatch] ", len(networkTable[bestMatch]))
			fmt.Println("best match interface ip address: ", e.IpAddr)
			if e.Up {
				if e.IsDefault {
					fmt.Println("Sending to default destination:", e.Default.String())
					SendIP(e.Default, protocolNum, packet)
					return nil
				}
				if protocolNum == 0 {
					fmt.Println("Best match address:", e.IpAddr.String())
				}
				if neighbor, exists := e.LookupTable[dest]; exists {
					//count to infinity
					if neighbor.Cost >= maxCost {
						continue // drop the package
					}

					if protocolNum == 0 {
						fmt.Println("Neighbor found, message:", string(message))
					}
					if neighbor.WillHop {
						if protocolNum == 0 {
							fmt.Println("Will hop to:", e.IpAddr.String())
						}
						SendIP(e.IpAddr, protocolNum, packet)
						return nil
					}
					_, err := neighbor.UdpConn.Write(packet)
					if err != nil {
						fmt.Println("Error writing to UDP connection:", err)
						return err
					}
					return err
				}
			}
		}
	} else {
		fmt.Println("No valid prefix match found for destination:", dest.String())
		// SendIP(e.Default, protocolNum, packet)
	}

	return errors.New("no valid route found")
}

// Populate the combined networkTable
func populateTable(fileName string) {
	lnxConfig, err := lnxconfig.ParseConfig(fileName)
	if err != nil {
		panic(err)
	}
	if len(lnxConfig.Interfaces) > 1 {
		isRouter = true
	} else {
		isRouter = false
	}
	ripUpdateRate = lnxConfig.RipPeriodicUpdateRate
	timeoutLimit = lnxConfig.RipTimeoutThreshold

	for _, iface := range lnxConfig.Interfaces {
		prefixForm := netip.PrefixFrom(iface.AssignedIP, iface.AssignedPrefix.Bits())
		entry := &NetworkEntry{
			Name:        iface.Name,
			IpPrefix:    prefixForm,
			IpAddr:      prefixForm.Addr(),
			UdpAddrPort: iface.UDPAddr,
			LookupTable: make(LookupTable),
			Up:          true,
			IsDefault:   false,
		}
		maskedPrefix := newPrefixFromAddr(prefixForm)
		fmt.Println("masked prefix returned by helper func: ", maskedPrefix)
		networkTable[maskedPrefix] = append(networkTable[maskedPrefix], entry)
	}

	for _, neighbor := range lnxConfig.Neighbors {
		for _, listOfEntries := range networkTable {
			for i := range listOfEntries {
				entry := listOfEntries[i]
				if entry.Name == neighbor.InterfaceName {
					maskedPrefix := newPrefixFromAddr(entry.IpPrefix)
					n := &Neighbor{
						DestAddr:      neighbor.DestAddr,
						UdpAddrPort:   neighbor.UDPAddr,
						InterfaceName: neighbor.InterfaceName,
						IpPrefix:      maskedPrefix,
						Cost:          1,
						WillHop:       false,
					}
					entry.LookupTable[neighbor.DestAddr] = n
					createUdpConn(n)
					for _, addr := range lnxConfig.RipNeighbors {
						if addr == neighbor.DestAddr {
							entry.RipNeighbors = append(entry.RipNeighbors, n)
							break
						}
					}
					break
				}
			}

		}
	}

	for prefix := range lnxConfig.StaticRoutes {
		entry := &NetworkEntry{
			IpPrefix:  prefix,
			Up:        true,
			IsDefault: true,
			Default:   lnxConfig.StaticRoutes[prefix],
		}
		maskedPrefix := newPrefixFromAddr(prefix)
		fmt.Println("masked prefix returned by helper func: ", maskedPrefix)
		networkTable[maskedPrefix] = append(networkTable[maskedPrefix], entry)
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

func newPrefixFromAddr(prefix netip.Prefix) netip.Prefix {
	networkAddr := prefix.Masked().Addr()
	return netip.PrefixFrom(networkAddr, prefix.Bits())
}
