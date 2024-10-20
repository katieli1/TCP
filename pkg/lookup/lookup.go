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

type Neighbor struct { // represents any interface that's reachable by this router/host
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

var RipNeighborsMap = make(map[netip.Addr]netip.Addr) // for routers

// Combined table for interfaces and static routes
var networkTable = make(map[netip.Prefix]*NetworkEntry)

type HandlerFunc func(message string, source netip.Addr, dest netip.Addr)

var handlerTable = make(map[uint8]HandlerFunc)

var isRouter bool

const maxPacketSize = 1400

var timeoutLimit time.Duration
var ripUpdateRate time.Duration

var maxCost = 16

func Initialize(fileName string) {
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
			go sendRipRequest(dest, true)
			go sendRIPData(dest)
		}
		go checkNeighbors()
	}

	done := make(chan struct{})
	go func() {
		REPL()
		close(done)
	}()

	<-done
}

func sendRIPData(dest netip.Addr) {
	for {
		time.Sleep(ripUpdateRate)
		sendRIPHelper(dest, false, nil)
	}
}

func Callback_test(msg string, source netip.Addr, dest netip.Addr) {
	fmt.Println("Received test packet: Src: " + source.String() + ", Dst: " + dest.String() + ", TTL: <ttl>, Data: " + msg)
}

func Callback_RIP(message string, source netip.Addr, dest netip.Addr) {
	nextHop := source
	var changed = false
	var changedEntry []*Neighbor
	var routes []RouteInfo
	entries := strings.Split(message, ";")
	typeOfMessage := strings.Split(entries[0], ",")[0]

	typeOfMessageInt, err := strconv.Atoi(typeOfMessage)
	if err != nil {
		return
	}

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

		value, _ := strconv.ParseUint(cleanedString, 10, 32)

		result := pkgUtils.Uint32ToIP(uint32(value))
		if err != nil {
			fmt.Println("Invalid address:", fields[2], "Error:", err)
			continue
		}
		routes = append(routes, RouteInfo{
			Cost:         cost,
			PrefixLength: prefixLength,
			Address:      pkgUtils.IpToUint32(result),
		})
	}

	if uint32(typeOfMessageInt) == 1 {
		for addr := range RipNeighborsMap {
			sendRIPHelper(addr, false, nil)
		}
		return
	}

	for _, route := range routes {
		//fmt.Println("start of route loop")
		address := pkgUtils.Uint32ToIP(route.Address)
		prefix := netip.PrefixFrom(address, route.PrefixLength)

		networkAddr := prefix.Masked().Addr()
		maskedPrefix := netip.PrefixFrom(networkAddr, prefix.Bits())
		if entry, exists := networkTable[maskedPrefix]; exists {

			if entry.Name != "" {
				continue
			}
			if neighbor, found := entry.LookupTable[address]; found {
				//poison reverse - split horizon
				newCost := route.Cost + 1
				if newCost > maxCost {
					continue
				}
				if (neighbor.NextHop == nextHop) || neighbor.Cost > newCost {
					if neighbor.Cost != newCost {
						changed = true
						changedEntry = append(changedEntry, neighbor)
					}
					neighbor.Cost = newCost
					neighbor.NextHop = nextHop
					entry.LookupTable[address].LastHeard = time.Now()
				}
			} else {
				entry.LookupTable[address] = &Neighbor{
					DestAddr: address,
					Cost:     route.Cost + 1,
					IpPrefix: maskedPrefix,
					NextHop:  nextHop,
					WillHop:  true,
				}
				changed = true
				changedEntry = append(changedEntry, entry.LookupTable[address])
			}

		} else {
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
			changedEntry = append(changedEntry, newEntry.LookupTable[address])

		}

	}
	if changed {
		for addr := range RipNeighborsMap {
			if len(changedEntry) > 0 {
				sendRIPHelper(addr, false, changedEntry)
			}
		}
	}
}

func sendRipRequest(dest netip.Addr, shouldLock bool) {
	startOfMessage := fmt.Sprintf("%d,%d;", 1, 0)
	messageBytes := []byte(startOfMessage + fmt.Sprintf("%d,%d,%d", 16, 10, pkgUtils.IpToUint32(RipNeighborsMap[dest])))
	headerBytes, err := createHeader(dest, RipNeighborsMap[dest], len(messageBytes))
	if err != nil {
		return
	}
	packet := append(headerBytes, messageBytes...)
	SendIP(dest, 200, packet, shouldLock, "sendIpRipRequest")
}

func sendRIPHelper(dest netip.Addr, shouldLock bool, manualEntries []*Neighbor) {
	var messageBuilder strings.Builder
	num_entries := 0

	if manualEntries == nil {
		if shouldLock {
			networkTableLock.RLock()
		}

		for _, entry := range networkTable {
			if entry.IsDefault {
				continue
			}
			for _, neighbor := range entry.LookupTable {
				var cost int
				cost = neighbor.Cost
				if dest == neighbor.NextHop {
					cost = 17
				}
				message := fmt.Sprintf("%d,%d,%d;", cost, entry.IpPrefix.Bits(), pkgUtils.IpToUint32(neighbor.DestAddr))
				messageBuilder.WriteString(message)
				num_entries += 1

			}
			me := fmt.Sprintf("%d,%d,%d;", 0, entry.IpPrefix.Bits(), pkgUtils.IpToUint32(entry.IpAddr))
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

	startOfMessage := fmt.Sprintf("%d,%d;", 2, num_entries)

	fullMessage := startOfMessage + message

	messageBytes := []byte(fullMessage)

	headerBytes, err := createHeader(dest, RipNeighborsMap[dest], len(message))
	if err != nil {
		return
	}
	packet := append(headerBytes, messageBytes...)
	SendIP(dest, 200, packet, shouldLock, "SendRip")
}

func createHeader(dest netip.Addr, src netip.Addr, length int) ([]byte, error) {
	header := &ipv4header.IPv4Header{
		Version:  4,
		Len:      20,
		TTL:      64,
		Dst:      dest,
		Src:      src,
		TotalLen: length + ipv4header.HeaderLen,
		Protocol: 200,
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

						// ONLY FOR DEBUGGING; DELETE FOR FINAL VERSION
						// nextHop := iface.LookupTable[neighborAddr].NextHop
						// fmt.Println(iface.Name + "      " + "Address " + neighborAddr.String() + " Prefix " + neighborAddr.String() + " Next hop " + nextHop.String())
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
				SendIP(dest, 0, packet, true, "repl")
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
			iface := networkTable[key]
			if iface.Name == ifname {
				iface.Up = up
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
				fmt.Println("Error reading from connection")
			}

			header, err := ipv4header.ParseHeader(buf[:ipv4header.HeaderLen])

			if err != nil {
				fmt.Println("Error parsing header:", err)
				continue
			}
			SendIP(header.Dst, uint8(header.Protocol), buf, true, "readConn")
		}
	}
}

func checkNeighbors() {

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

func removeNeighbor(ip netip.Addr) { // removes IP address from every NetworkEntry's LookupTable
	for i := range networkTable {
		for n := range networkTable[i].LookupTable {
			if networkTable[i].LookupTable[n].NextHop == ip {
				delete(networkTable[i].LookupTable, n) // remove this entry from the LookupTabl
			}
		}

		neighbor, exists := networkTable[i].LookupTable[ip]

		if exists {
			if neighbor.UdpConn != nil {
				neighbor.UdpConn.Close()
			}
			delete(networkTable[i].LookupTable, ip) // remove this entry from the LookupTabl

		}

		if i.Contains(ip) {
			delete(networkTable, i)
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

func SendIP(dest netip.Addr, protocolNum uint8, packet []byte, shouldLock bool, from string) error {
	header, err := ipv4header.ParseHeader(packet[:ipv4header.HeaderLen])
	if header.Src == netip.AddrFrom4([4]byte{0, 0, 0, 0}) || !header.Src.IsValid() {
		fmt.Println("initializing src")
		var src netip.Addr
		for i := range networkTable {
			for _, n := range networkTable[i].LookupTable {
				if n.NextHop == dest && networkTable[i].IpAddr.IsValid() {
					src = networkTable[i].IpAddr
				}
			}
			fmt.Println(src.String())
			header.Src = src
		}

	}

	if err != nil {
		return fmt.Errorf("error parsing header: %w", err)
	}

	if header.TTL == 0 {
		return errors.New("TTL expired")
	}

	header.TTL -= 1

	headerSize := header.Len
	headerBytes := packet[:headerSize]
	checksumFromHeader := uint16(header.Checksum)
	computedChecksum := ValidateChecksum(headerBytes, checksumFromHeader)

	if computedChecksum != checksumFromHeader {
		return errors.New("checksum is bad")
	}

	message := packet[headerSize:]

	var bestMatch netip.Prefix
	if shouldLock {
		networkTableLock.RLock()
	}

	for prefix := range networkTable {
		addr := networkTable[prefix].IpAddr
		if addr == header.Dst && networkTable[prefix].Name != "" {

			if callback, found := handlerTable[protocolNum]; found {
				callback(string(message), header.Src, header.Dst)
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

	if bestMatch.IsValid() {

		e := networkTable[bestMatch]
		if e.Up {
			// if !header.Src.IsValid() && !isRouter {
			// 	fmt.Println("in if statement")
			// 	header.Src = e.IpAddr
			// }

			headerBytes, err = header.Marshal()
			if err != nil {
				return errors.New("error marshalling header")
			}

			if e.IsDefault {
				SendIP(e.Default, protocolNum, packet, shouldLock, "sendIpDefault")
				return nil
			}

			if neighbor, exists := e.LookupTable[dest]; exists {
				//count to infinity
				if neighbor.Cost >= maxCost {
					return nil
				}

				if neighbor.WillHop {
					SendIP(e.IpAddr, protocolNum, packet, shouldLock, "sendIpNextHop")
					return nil
				}
				_, err := neighbor.UdpConn.Write(packet)
				if err != nil {
					return err
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

	for _, iface := range lnxConfig.Interfaces {
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

	for _, neighbor := range lnxConfig.Neighbors {
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
				createUdpConn(n)
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

func getMaskedPrefix(prefix netip.Prefix) netip.Prefix {
	networkAddr := prefix.Masked().Addr()
	return netip.PrefixFrom(networkAddr, prefix.Bits())
}
