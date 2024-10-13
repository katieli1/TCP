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
	"time"
	"strconv"
)

type NetworkEntry struct {
	IpPrefix    netip.Prefix
	IpAddr      netip.Addr
	UdpAddrPort netip.AddrPort
	LookupTable LookupTable // Lookup table for neighbors
	Name        string
	Up          bool
	IsDefault   bool
	Default netip.Addr
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
	IpPrefix netip.Prefix
	NextHop netip.Addr
	InterfaceName string
	Cost int
	WillHop bool
}

type LookupTable map[netip.Addr]*Neighbor

// Combined table for interfaces and static routes
var networkTable = make(map[netip.Prefix]*NetworkEntry)

type HandlerFunc func(string)

var handlerTable = make(map[uint8]HandlerFunc)

var RipNeighbors []*Neighbor
var isRouter bool

const maxPacketSize = 4096

func Initialize(fileName string) {
	populateTable(fileName)
	// RegisterRecvHandler(200, callback)
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
			go sendRIPData()
		}
	}

	done := make(chan struct{})
	go func() {
		REPL()
		close(done)
	}()

	<-done
}
func callback(message string, nextHop netip.Addr) {
    // Parse the message into a list of RouteInfo structs
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

        addr, err := netip.ParseAddr(fields[2])
        if err != nil {
            fmt.Println("Invalid address:", fields[2]) // Log invalid addresses
            continue
        }

        routes = append(routes, RouteInfo{
            Cost:         cost,
            PrefixLength: prefixLength,
            Address:      addr,
        })
    }

    for _, route := range routes {
        prefix := netip.PrefixFrom(route.Address, route.PrefixLength)

        if entry, exists := networkTable[prefix]; exists {
            if neighbor, found := entry.LookupTable[route.Address]; found {
                // Update cost if the new path is shorter
                if neighbor.NextHop == nextHop || neighbor.Cost > route.Cost+1 {
                    neighbor.Cost = route.Cost + 1
                    neighbor.NextHop = nextHop
                }
            } else {
                entry.LookupTable[route.Address] = &Neighbor{
                    DestAddr: route.Address,
                    Cost:     route.Cost + 1,
                    IpPrefix: prefix,
                    NextHop:  nextHop,
                    WillHop:  true,
                }
            }
        } else {
            // Add a new entry to the networkTable
            newEntry := &NetworkEntry{
                IpPrefix:    prefix,
                IpAddr:      nextHop, // Set correct IP address
                LookupTable: make(map[netip.Addr]*Neighbor),
                Up:          true,
                IsDefault:   false,
            }
            newEntry.LookupTable[route.Address] = &Neighbor{
                DestAddr: route.Address,
                Cost:     route.Cost + 1,
                IpPrefix: prefix,
                NextHop:  nextHop,
                WillHop:  true,
            }
            networkTable[prefix] = newEntry
        }
    }
}

func sendRIPData() {
    for {
        time.Sleep(5 * time.Second)
        var messageBuilder strings.Builder

        // Iterate over each NetworkEntry in the network table
        for _, entry := range networkTable {
            if entry.IsDefault {
                continue
            }
            for _, neighbor := range entry.LookupTable {
                // Create a RouteInfo message
                message := fmt.Sprintf("%d,%d,%s;", neighbor.Cost, entry.IpPrefix.Bits(), neighbor.DestAddr.String())
                messageBuilder.WriteString(message)
            }
        }

        // Remove the trailing ';' character from the message
        message := strings.TrimSuffix(messageBuilder.String(), ";")

        if message == "" {
            fmt.Println("No routes to send.")
            continue // Skip sending if there's no message
        }

        messageBytes := []byte(message)

        // Send the constructed message to each neighbor's UDP connection
        for _, neighbor := range RipNeighbors {
            header := &ipv4header.IPv4Header{
                Version:   4,
                Len:       20,
                TTL:       64,
                Dst:       neighbor.DestAddr,
                Src:       networkTable[neighbor.IpPrefix].IpAddr,
                TotalLen:  len(message) + ipv4header.HeaderLen,
                Protocol:  200,
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
            fmt.Println("Sending message:", message) // Log the message being sent
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
			if networkTable[key].Name == ifname {
				networkTable[key].Up = up
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
			// for header.TotalLen > bytesRead { // read until the total message is received
			// 	newBuf := make([]byte, maxPacketSize)
			// 	b, err := conn.Read(newBuf)
			// 	if err != nil {
			// 		// TODO
			// 	}
			// 	buf = append(buf, newBuf...)
			// 	bytesRead += b
			// }
			if err != nil {
				fmt.Println("Error parsing header:", err)
				continue
			}
		
		var protocol uint8 = 0
		if header.Protocol == 200 {
			protocol = 200
		}
		SendIP(header.Dst, protocol, buf)
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
	if protocolNum == 0 {
		fmt.Println("Message in Send IP: " + string(message))
	}
	// Iterate through the networkTable to find the longest prefix match
	for prefix, entry := range networkTable {
		if protocolNum == 0 {
			fmt.Println("dest: " + dest.String())
		}
		if prefix.Contains(dest) {
			if header.Dst == networkTable[prefix].IpAddr{
				if protocolNum == 200 {
					callback(string(message), header.Src)
					return nil
				}
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
		if bestMatch.Up {
			if bestMatch.IsDefault{
				SendIP(bestMatch.Default, protocolNum, packet)
				return nil
			}
			if protocolNum == 0 {
				fmt.Println("bestMatch: " + bestMatch.IpAddr.String())
			}
			if neighbor, exists := bestMatch.LookupTable[dest]; exists {
				if protocolNum == 0 {
					fmt.Println("neighbor: " + string(message))
				}
				if neighbor.WillHop {
					SendIP(bestMatch.IpAddr, protocolNum, packet)
					return nil
				}
				neighbor.UdpConn.Write(packet)
				return nil
			}
		}
		return nil
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

	for _, iface := range lnxConfig.Interfaces {
		prefixForm := netip.PrefixFrom(iface.AssignedIP, iface.AssignedPrefix.Bits())
		entry := &NetworkEntry{
			Name:        iface.Name,
			IpPrefix:    prefixForm,
			IpAddr:      prefixForm.Addr(),
			UdpAddrPort: iface.UDPAddr,
			LookupTable: make(LookupTable),
			Up:          true,
			IsDefault: false,
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
					IpPrefix: entry.IpPrefix,
					Cost: 1,
					WillHop:false,
				}
				entry.LookupTable[neighbor.DestAddr] = n
				createUdpConn(n)
				for _, addr := range lnxConfig.RipNeighbors {
					if addr == neighbor.DestAddr {
						RipNeighbors = append(RipNeighbors, n)
						break
					}
				}
				break
			}
		}
	}

	for prefix := range lnxConfig.StaticRoutes {
		entry := &NetworkEntry{
			IpPrefix:    prefix,
			Up:          true,
			IsDefault: true,
			Default: lnxConfig.StaticRoutes[prefix],
		}
		networkTable[prefix] = entry
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
