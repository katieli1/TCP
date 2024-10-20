package lookup

import (
	"bufio"
	"errors"
	"fmt"
	ipv4header "ip/pkg/header-parser"
	"ip/pkg/lnxconfig"
	"ip/pkg/pkgUtils"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/netstack/tcpip/header"
)

var networkTableLock sync.RWMutex

type NetworkEntry struct { // represents an interface
	IpPrefix     netip.Prefix
	IpAddr       netip.Addr
	UdpAddrPort  *netip.AddrPort
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
	Address      uint32
}

type Neighbor struct { // represents any interface that's reachable by this router/host (not necessarily immediate neighbor)
	UdpConn       net.Conn
	DestAddr      netip.Addr
	UdpAddrPort   netip.AddrPort
	IpPrefix      netip.Prefix
	NextHop       netip.Addr // the next hop for THIS router/host in order to reach this neighbor
	InterfaceName string
	Cost          int
	WillHop       bool
	LastHeard     time.Time
	IsRouter      bool
}

type LookupTable map[netip.Addr]*Neighbor

var RipNeighborsMap = make(map[netip.Addr]netip.Addr) // for routers

// Combined table for interfaces and static routes
var networkTable = make(map[netip.Prefix]*NetworkEntry)

type HandlerFunc func(message string, source netip.Addr, dest netip.Addr, ttl int)

var handlerTable = make(map[uint8]HandlerFunc)

var isRouter bool

const maxPacketSize = 1400

var timeoutLimit time.Duration
var ripUpdateRate time.Duration

var maxCost = 16

func Initialize(fileName string) { // called on startup to populate table
	populateTable(fileName)
	networkTableLock.RLock()
	for _, entry := range networkTable {

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
		}
	}

	networkTableLock.RUnlock()
	if isRouter {
		for dest := range RipNeighborsMap {
			go sendRipRequest(dest, true) // ask for RIP data from RIP neighbors
			go sendRIPData(dest)          // continuously send RIP data about this router to RIP neighbors
		}
		go checkNeighbors() // start thread that continuously checks whether RIP neighbors have timed out
	}

	done := make(chan struct{})
	go func() {
		repl()
		close(done)
	}()

	<-done
}

func sendRIPData(dest netip.Addr) {
	for { // loop infinitely
		time.Sleep(ripUpdateRate)
		sendRIPHelper(dest, false, nil) // send RIP data
	}
}

func Callback_test(msg string, source netip.Addr, dest netip.Addr, ttl int) { // callback for test packets
	fmt.Println("Received test packet: Src: " + source.String() + ", Dst: " + dest.String() + ", TTL: " + fmt.Sprintf("%d", ttl) + ", Data: " + msg)
}

func Callback_RIP(message string, source netip.Addr, dest netip.Addr, ttl int) { // callback for RIP updates that updates tables
	nextHop := source // the address that we heard about this data from
	var changed = false
	var changedEntries []*Neighbor // keep track of any entries that changed (to be able to send triggered updates)
	var routes []RouteInfo
	entries := strings.Split(message, ";")
	typeOfMessage := strings.Split(entries[0], ",")[0]

	typeOfMessageInt, err := strconv.Atoi(typeOfMessage) // check whether it's a request for RIP data or a packet that contains RIP data
	if err != nil {
		return
	}

	// parse data
	entriesWithoutMetadata := entries[1:]
	for _, entry := range entriesWithoutMetadata {
		fields := strings.Split(entry, ",")
		if len(fields) != 3 {
			continue
		}

		cost, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}

		prefixLength, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		cleanedString := strings.TrimSpace(strings.ReplaceAll(fields[2], "\x00", ""))
		addr, err := strconv.Atoi(cleanedString)
		if err != nil {
			fmt.Println("Invalid address:", fields[2], "Error:", err)
			continue
		}

		result := pkgUtils.Uint32ToIP(uint32(addr))
		routes = append(routes, RouteInfo{
			Cost:         cost,
			PrefixLength: prefixLength,
			Address:      pkgUtils.IpToUint32(result),
		})
	}

	if uint32(typeOfMessageInt) == 1 { // if it's a request for RIP data, send RIP data and return
		for addr := range RipNeighborsMap {
			sendRIPHelper(addr, false, nil)
		}
		return
	}

	for _, route := range routes { // for each route we received info about from the RIP data
		address := pkgUtils.Uint32ToIP(route.Address)
		prefix := netip.PrefixFrom(address, route.PrefixLength)

		networkAddr := prefix.Masked().Addr()
		maskedPrefix := netip.PrefixFrom(networkAddr, prefix.Bits())
		if entry, exists := networkTable[maskedPrefix]; exists { // if we already know about the prefix

			if entry.Name != "" {
				continue
			}
			if neighbor, found := entry.LookupTable[address]; found { // if we already know about the address
				//poison reverse - split horizon
				newCost := route.Cost + 1
				if newCost > maxCost {
					continue
				}
				if (neighbor.NextHop == nextHop) || neighbor.Cost > newCost { // update cost if necessary
					if neighbor.Cost != newCost {
						changed = true
						changedEntries = append(changedEntries, neighbor)
					}
					neighbor.Cost = newCost
					neighbor.NextHop = nextHop
					entry.LookupTable[address].LastHeard = time.Now()
				}
			} else { // if we know about the prefix but not address, add the address to our lookup table
				entry.LookupTable[address] = &Neighbor{
					DestAddr: address,
					Cost:     route.Cost + 1,
					IpPrefix: maskedPrefix,
					NextHop:  nextHop,
					WillHop:  true,
				}
				changed = true
				changedEntries = append(changedEntries, entry.LookupTable[address])
			}

		} else { // if we don't know about the prefix, construct a new entry to represent this subnet
			newEntry := &NetworkEntry{
				IpPrefix:    maskedPrefix,
				IpAddr:      nextHop,
				LookupTable: make(map[netip.Addr]*Neighbor),
				Up:          true,
				IsDefault:   false,
			}
			newEntry.LookupTable[address] = &Neighbor{
				DestAddr:  address,
				Cost:      route.Cost + 1,
				IpPrefix:  maskedPrefix,
				NextHop:   nextHop,
				WillHop:   true,
				LastHeard: time.Now(),
			}
			networkTable[maskedPrefix] = newEntry
			changed = true
			changedEntries = append(changedEntries, newEntry.LookupTable[address])

		}

	}
	if changed {
		for addr := range RipNeighborsMap {
			if len(changedEntries) > 0 { // if any entries have changed
				sendRIPHelper(addr, false, changedEntries) // send a RIP update about each changed entry
			}
		}
	}
}

func sendRipRequest(dest netip.Addr, shouldLock bool) { // method that sends request to receive RIP data from neighbors
	startOfMessage := fmt.Sprintf("%d,%d;", 1, 0)
	messageBytes := []byte(startOfMessage + fmt.Sprintf("%d,%d,%d", 16, 10, pkgUtils.IpToUint32(RipNeighborsMap[dest])))
	headerBytes, err := createHeader(dest, RipNeighborsMap[dest], len(messageBytes), 200, 64)
	if err != nil {
		return
	}
	packet := append(headerBytes, messageBytes...)
	SendIP(dest, 200, packet, shouldLock)
}

// helper that sends RIP data about a list of neighbors to all RIP neighbors
func sendRIPHelper(dest netip.Addr, shouldLock bool, manualEntries []*Neighbor) {
	var messageBuilder strings.Builder
	num_entries := 0

	if manualEntries == nil {
		if shouldLock {
			networkTableLock.RLock()
		}

		for _, entry := range networkTable { // for every interface

			if entry.IsDefault {
				continue
			}
			for _, neighbor := range entry.LookupTable { // for every neighbor the interface can reach
				var cost int
				cost = neighbor.Cost
				if dest == neighbor.NextHop {
					cost = 17
				}
				message := fmt.Sprintf("%d,%d,%d;", cost, entry.IpPrefix.Bits(), pkgUtils.IpToUint32(neighbor.DestAddr))
				messageBuilder.WriteString(message) // add info about it to the message
				num_entries += 1

			}
			me := fmt.Sprintf("%d,%d,%d;", 0, entry.IpPrefix.Bits(), pkgUtils.IpToUint32(entry.IpAddr)) // add this interface to the message
			messageBuilder.WriteString(me)
			num_entries += 1

		}
		if shouldLock {
			networkTableLock.RUnlock()
		}

	} else {
		for _, neighbor := range manualEntries {

			var cost int
			cost = neighbor.Cost
			if dest == neighbor.NextHop {
				cost = 17
			}
			message := fmt.Sprintf("%d,%d,%d;", cost, neighbor.IpPrefix.Bits(), pkgUtils.IpToUint32(neighbor.DestAddr))
			messageBuilder.WriteString(message)
			num_entries += 1
		}
	}
	message := strings.TrimSuffix(messageBuilder.String(), ";")
	if message == "" {
		fmt.Println("No routes to send.")
		return
	}

	// construct message about RIP data and send
	startOfMessage := fmt.Sprintf("%d,%d;", 2, num_entries)

	fullMessage := startOfMessage + message

	messageBytes := []byte(fullMessage)

	headerBytes, err := createHeader(dest, RipNeighborsMap[dest], len(message), 200, 64)
	if err != nil {
		return
	}
	packet := append(headerBytes, messageBytes...)
	SendIP(dest, 200, packet, shouldLock)
}

// helper to create header for packets
func createHeader(dest netip.Addr, src netip.Addr, length int, protocol int, TTL int) ([]byte, error) {
	header := &ipv4header.IPv4Header{
		Version:  4,
		Len:      20,
		TTL:      TTL,
		Dst:      dest,
		Src:      src,
		TotalLen: length + ipv4header.HeaderLen,
		Protocol: protocol,
	}

	headerBytes, err := header.Marshal()
	if err != nil {
		fmt.Println("Error marshaling header:", err)
		return nil, err // Return nil and the error
	}

	header.Checksum = int(ComputeChecksum(headerBytes))
	headerBytes, err = header.Marshal()
	if err != nil {
		fmt.Println("Error marshaling header after checksum:", err)
		return nil, err // Return nil and the error
	}

	return headerBytes, nil //return the headerBytes and nil for no error
}

// function that registers callback functions; called by hosts and routers
func RegisterRecvHandler(protocolNum uint8, callbackFunc HandlerFunc) error {
	if protocolNum != 0 && protocolNum != 200 {
		return errors.New("Invalid protocolNum")
	}
	handlerTable[protocolNum] = callbackFunc
	return nil
}

func repl() { // manages command line interface
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
			for _, iface := range networkTable {
				if iface.UdpAddrPort != nil {
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
				iface := networkTable[key]
				if iface.Up { // don't print neighbors for ifaces that are down
					for neighborAddr := range iface.LookupTable {
						if iface.LookupTable[neighborAddr].UdpConn != nil {
							udpConn := iface.LookupTable[neighborAddr].UdpConn.RemoteAddr().String() // TODO: make sure remote addr (not local) is correct
							fmt.Println(iface.Name + "      " + neighborAddr.String() + "  " + udpConn)
						}
					}
				}

			}
		} else if input == "lr" { // list routes
			fmt.Println("T       Prefix        Next hop   Cost")
			for key := range networkTable {
				iface := networkTable[key]
				if iface.Up { // don't print neighbors for ifaces that are down

					var seenPrefixes []string
					for neighborAddr := range iface.LookupTable {

						neighbor := iface.LookupTable[neighborAddr]

						var t string
						if neighbor.DestAddr == neighbor.NextHop {
							t = "L       "
						} else {
							if isRouter {
								t = "R       "
							} else {
								t = "S       "
							}
						}

						seen := false
						for _, prefix := range seenPrefixes {
							if prefix == iface.IpPrefix.String() {
								seen = true
							}
						}
						if seen {
							continue
						}
						seenPrefixes = append(seenPrefixes, iface.IpPrefix.String())

						var interfaceName string
						for j := range networkTable {
							e, exists := networkTable[j].LookupTable[neighbor.NextHop]
							if exists {
								interfaceName = e.InterfaceName
								break
							}
						}
						fmt.Println(t+iface.IpPrefix.String()+"   "+interfaceName+"       ", neighbor.Cost-1)
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

				// need to create header
				header := &ipv4header.IPv4Header{Version: 4, Len: 20, TTL: 64, Dst: dest, TotalLen: len(words[2]) + ipv4header.HeaderLen} // determining source is complicated
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
				packet := append(headerBytes, payload...)
				SendIP(dest, 0, packet, true)
			}

		} else {
			fmt.Println("Invalid command. Valid commands include li, ln, lr, up <ifname>, down <ifname>, send <addr> <message ...>, and q to quit.")
		}
	}
}

// helper that sets state to up/down when requested by the CLI
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
			iface := networkTable[key]
			if iface.Name == ifname {
				iface.Up = up
			}
		}
	}
}

func readConn(iface *NetworkEntry, conn net.Conn) { // thread that continously reads from a connection for an interface

	for {

		if iface.Up {
			buf := make([]byte, maxPacketSize)

			_, err := conn.Read(buf)

			if err != nil {
				fmt.Println("Error reading from connection")
			}

			header, err := ipv4header.ParseHeader(buf[:ipv4header.HeaderLen])
			if err != nil {
				fmt.Println("Error parsing header:", err)
				continue
			}
			if header.Protocol == 0 {
				fmt.Println("recieved src: ", header.Src)

			}
			SendIP(header.Dst, uint8(header.Protocol), buf, true) // process data
		}
	}
}

func checkNeighbors() { // continously checks whether neighbors have timed out; if so, remove

	for {
		networkTableLock.Lock()
		for i := range networkTable {
			iface := networkTable[i]

			if isRouter {
				for addr := range iface.LookupTable {
					lastHeard := iface.LookupTable[addr].LastHeard
					if !lastHeard.IsZero() {
						if time.Since(lastHeard) >= timeoutLimit {
							removeNeighbor(addr) // removes IP address from every NetworkEntry's LookupTable
						}
					}
				}
			}

		}
		networkTableLock.Unlock()

	}
}

// helper to remove neighbors when we don't hear from them within the timeout limit
func removeNeighbor(ip netip.Addr) { // removes IP address from every NetworkEntry's LookupTable
	for i := range networkTable {
		for n := range networkTable[i].LookupTable {
			if networkTable[i].LookupTable[n].NextHop == ip {
				delete(networkTable[i].LookupTable, n) // remove this entry from the LookupTable
			}
		}

		neighbor, exists := networkTable[i].LookupTable[ip]

		if exists {
			if neighbor.UdpConn != nil {
				neighbor.UdpConn.Close()
			}
			delete(networkTable[i].LookupTable, ip) // remove this entry from the LookupTable

		}

		if i.Contains(ip) {
			delete(networkTable, i)
		}

	}

}

func createUdpConn(neighbor *Neighbor) {
	addrPort := neighbor.UdpAddrPort
	udpAddr := &net.UDPAddr{
		IP:   addrPort.Addr().AsSlice(),
		Port: int(addrPort.Port()),
	}

	// Create a UDP connection (for sending)
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		fmt.Println("Error dialing UDP connection:", err)
		return
	}
	neighbor.UdpConn = conn
}

// function that checks whether TTL/checksum are valid, whether this packet is for me (if so, invoke callback)
// and then sends to next hop if the packet is not for me
func SendIP(dest netip.Addr, protocolNum uint8, packet []byte, shouldLock bool) error {
	header, err := ipv4header.ParseHeader(packet[:ipv4header.HeaderLen])

	// determine which interface to send out of to set source IP address
	if header.Src == netip.AddrFrom4([4]byte{0, 0, 0, 0}) || !header.Src.IsValid() {
		fmt.Println("initializing src")
		var src netip.Addr
		for i := range networkTable {
			if networkTable[i].Name != "" { //only interfaces that are my own have names
				for _, n := range networkTable[i].LookupTable {
					if n.NextHop == dest && networkTable[i].IpAddr.IsValid() {
						src = networkTable[i].IpAddr
					}
				}
				header.Src = src
			}

		}

	}

	if err != nil {
		return fmt.Errorf("error parsing header: %w", err)
	}

	if header.TTL == 0 { // drop if TTL expired
		return errors.New("TTL expired")
	}

	headerSize := header.Len
	headerBytes := packet[:headerSize]
	checksumFromHeader := uint16(header.Checksum)
	computedChecksum := ValidateChecksum(headerBytes, checksumFromHeader)

	// drop if checksum is bad
	if computedChecksum != checksumFromHeader {
		return errors.New("checksum is bad")
	}

	message := packet[headerSize:]

	var bestMatch netip.Prefix
	if shouldLock {
		networkTableLock.RLock()
	}

	for prefix := range networkTable { // find best-match prefix
		addr := networkTable[prefix].IpAddr
		if addr == header.Dst && networkTable[prefix].Name != "" { // if this packet is for me

			if callback, found := handlerTable[protocolNum]; found {
				callback(string(message), header.Src, header.Dst, header.TTL) // invoke callback function (updates table for RIP, prints for test packets)
				if shouldLock {
					networkTableLock.RUnlock()
				}
				return nil
			}
		}
		if prefix.Contains(dest) && (bestMatch.Bits() == 0 || prefix.Bits() > bestMatch.Bits()) {
			bestMatch = getMaskedPrefix(prefix)
		}
	}
	if shouldLock {
		networkTableLock.RUnlock()
	}

	if bestMatch.IsValid() { // if best match was found

		e := networkTable[bestMatch]
		if e.Up { // don't send through ifaces that are Down
			headerBytes, err = header.Marshal()
			if err != nil {
				return errors.New("error marshalling header")
			}

			if e.IsDefault { // if it's going through a default static route
				return SendIP(e.Default, protocolNum, packet, shouldLock) // resend through static route
			}

			if neighbor, exists := e.LookupTable[dest]; exists {
				//count to infinity
				if neighbor.Cost >= maxCost {
					return nil
				}

				if neighbor.WillHop { // if the next destination is not the final destination
					return SendIP(e.IpAddr, protocolNum, packet, shouldLock) // send to next destination
				}

				// construct header and write to correct UDP connection
				headerBytes, err := createHeader(header.Dst, header.Src, len(message), header.Protocol, header.TTL-1)
				if err != nil {
					return err
				}

				totalMessage := append(headerBytes, message...)
				_, err2 := neighbor.UdpConn.Write(totalMessage)
				if err2 != nil {
					return err2
				}
				return err
			}
		}

	} else {
		fmt.Println("No valid prefix match found for destination:", dest.String())
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

	for _, iface := range lnxConfig.Interfaces { // populate interfaces
		prefixForm := netip.PrefixFrom(iface.AssignedIP, iface.AssignedPrefix.Bits())
		entry := &NetworkEntry{
			Name:        iface.Name,
			IpPrefix:    prefixForm,
			IpAddr:      prefixForm.Addr(),
			UdpAddrPort: &iface.UDPAddr,
			LookupTable: make(LookupTable),
			Up:          true,
			IsDefault:   false,
		}
		maskedPrefix := getMaskedPrefix(prefixForm)
		networkTable[maskedPrefix] = entry
	}

	for _, neighbor := range lnxConfig.Neighbors { //populate neighbors
		for _, entry := range networkTable {
			if entry.Name == neighbor.InterfaceName {
				maskedPrefix := getMaskedPrefix(entry.IpPrefix)
				n := &Neighbor{
					DestAddr:      neighbor.DestAddr,
					UdpAddrPort:   neighbor.UDPAddr,
					InterfaceName: neighbor.InterfaceName,
					IpPrefix:      maskedPrefix,
					NextHop:       neighbor.DestAddr,
					Cost:          1,
					WillHop:       false,
				}
				entry.LookupTable[neighbor.DestAddr] = n
				createUdpConn(n) //create UDP connection to immediate neighbors
				for _, addr := range lnxConfig.RipNeighbors {
					if addr == neighbor.DestAddr {
						RipNeighborsMap[addr] = entry.IpAddr
						entry.RipNeighbors = append(entry.RipNeighbors, n)
						break
					}
				}
				break
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
		maskedPrefix := getMaskedPrefix(prefix)
		networkTable[maskedPrefix] = entry
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

func getMaskedPrefix(prefix netip.Prefix) netip.Prefix { //helper to mask prefixes so that they're consistent keys in networkTable
	networkAddr := prefix.Masked().Addr()
	return netip.PrefixFrom(networkAddr, prefix.Bits())
}
