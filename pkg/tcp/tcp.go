package tcp

import (
	"bufio"
	"fmt"
	"github.com/google/netstack/tcpip/header"
	"ip/pkg/iptcp_utils"
	"ip/pkg/lookup"
	"ip/pkg/pkgUtils"
	state "ip/pkg/tcp_states"
	"math/rand"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

type TCPMetadata struct {
	TCB        []byte
	isReceiver bool
	LastSeen   int16
	Next       int16
	Head       int16
	State      state.TCPState
}
type VListener struct {
	Port int16
	Chan chan (*pkgUtils.VTCPConn)
}
type OrderInfo struct {
    Port     int16
    VConn    *pkgUtils.VTCPConn
}

var fourtupleOrder []OrderInfo

var connectionTable = make(map[pkgUtils.VTCPConn]*TCPMetadata)
var listenerTable = make(map[int16]*VListener)
var bufsize = 1024
var sid = 0

func Initialize(fileName string) {
	go lookup.Initialize(fileName)

	done := make(chan struct{})
	go func() {
		repl()
		close(done)
	}()

	<-done
}

func repl() {

	fmt.Println("Welcome to the CLI! Valid commands include li, ln, lr, up <ifname>, down <ifname>, send <addr> <message ...>, and q to quit.")
	reader := bufio.NewReader(os.Stdin)
	for {
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		words := strings.Fields(input)

		if input == "q" { // quit
			break
		} else if words[0] == "a" { // listen and accept on a port
			port := words[1]

			num, err := strconv.ParseInt(port, 10, 16)
			if err != nil {
				fmt.Println("Error:", err)

			} else {
				go ACommand(int16(num))
			}

		} else if words[0] == "c" { // connect to a socket
			ip, err := netip.ParseAddr(words[1])
			if err != nil {
				fmt.Println("Error:", err)

			}
			port, err := strconv.ParseInt(words[2], 10, 16)
			if err != nil {
				fmt.Println("Error:", err)

			}
			VConnect(ip, int16(port))

		} else if words[0] == "s" { // send data using a socket

		} else if words[0] == "cl" { // close

		} else if words[0] == "ls" {
			fmt.Printf("%-10s %-15s %-10s %-15s %-10s %-10s\n", "SID", "LAddr", "LPort", "RAddr", "RPort", "Status")

			for index, v := range fourtupleOrder {
				if v.VConn != nil {
				// If the VConn is not nil, handle VTCPConn case
					if result, exists := connectionTable[*v.VConn]; exists {
						fmt.Printf("%-10d %-15s %-10s %-15s %-10s %-10s\n",
							index,                              // SID as index
							v.VConn.SourceIp.String(),          // LAddr
							strconv.Itoa(int(v.VConn.SourcePort)), // LPort
							v.VConn.DestIp.String(),            // RAddr
							strconv.Itoa(int(v.VConn.DestPort)), // RPort
							result.State)                       // Status
					}
				}else {
						// Handle case where VTCPConn exists but not in connectionTable
						fmt.Printf("%-10d %-15s %-10s %-15s %-10s %-10s\n",
							index,       // SID as index
							"0.0.0.0",   // LAddr placeholder for listener
							strconv.Itoa(int(v.Port)), // LPort as the uint16 listener port
							"0.0.0.0",   // RAddr placeholder for listener
							"0",         // RPort placeholder
							"LISTEN")    // Default listener status
				}
			}
		} else if words[0] == "sf" {

		} else if words[0] == "rf" {

		} else if words[0] == "r" { // receive data on a socket

		} else {
			fmt.Println("Invalid command. Valid commands include li, ln, lr, up <ifname>, down <ifname>, send <addr> <message ...>, and q to quit.")
		}
	}
}

func VListen(port int16) *VListener {
	return &VListener{Port: port, Chan: make(chan *pkgUtils.VTCPConn)}
}

func ACommand(port int16) {
	listenConn := VListen(port)
	listenerTable[port] = listenConn
	fourtupleOrder = append(fourtupleOrder, OrderInfo{port,nil})
	for {
		fourTuple, ok := <-listenConn.Chan
		if !ok {
			fmt.Println("failed")
		}
		fmt.Println("send accept now")
		clientConn, err := listenConn.VAccept(*fourTuple)
		fmt.Println("send accept now", clientConn, err)
	}
}

func (*VListener) VAccept(fourTuple pkgUtils.VTCPConn) (*pkgUtils.VTCPConn, error) {
	connectionTable[fourTuple] = &TCPMetadata{
		isReceiver: true,
		LastSeen:   0,
		Next:       0,
		Head:       0,
		State:      state.SYN_RECEIVED,
	}
fourtupleOrder = append(fourtupleOrder, OrderInfo{0, &fourTuple}) // Assuming `fourTuple` is a value



	bytes, err := pkgUtils.Marshal(fourTuple)
	if err != nil {
		return nil, err
	}

	err = sendTCPPacket(fourTuple.SourceIp, fourTuple.DestIp, fourTuple.SourcePort, fourTuple.DestPort,1,1, header.TCPFlagSyn|header.TCPFlagAck, bytes)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func Callback_TCP(msg []byte, source netip.Addr, dest netip.Addr, ttl int) {
	// FOR VCONNECT:
	// marshal into 4-tuple
	tcpHeaderAndData := []byte(msg)

	// Parse the TCP header into a struct
	tcpHdr := iptcp_utils.ParseTCPHeader(tcpHeaderAndData)

	// Get the payload
	tcpPayload := tcpHeaderAndData[tcpHdr.DataOffset:]

	tcpChecksumFromHeader := tcpHdr.Checksum // Save original
	tcpHdr.Checksum = 0
	fmt.Println("source: ", source.String())
	fmt.Println("dest: ", dest.String())

	tcpComputedChecksum := iptcp_utils.ComputeTCPChecksum(&tcpHdr, source, dest, tcpPayload)

	if tcpComputedChecksum != tcpChecksumFromHeader {
		fmt.Println("Error: bad checksum :(")
	}

	fourTuple := &pkgUtils.VTCPConn{}
	err := fourTuple.Unmarshal(tcpPayload)
	if err != nil {
		fmt.Println("error unmarshalling")
	}

	c := &pkgUtils.VTCPConn{ // set source addr by using getter
		SourceIp:   fourTuple.DestIp,
		SourcePort: fourTuple.DestPort,
		DestIp:     fourTuple.SourceIp,
		DestPort:   fourTuple.SourcePort,
	}

	// if ALREADY EXISTS, we are not receiving a VConnect. we should update the buffer in connection table

	connection, exists := connectionTable[*c]
	if exists {
		if connection.State == state.SYN_RECEIVED {
			connection.State = state.ESTABLISHED
			fmt.Println("Got here! ", state.SYN_RECEIVED)
			return
		}
		if connection.State == state.SYN_SENT {
			connection.State = state.ESTABLISHED
			fmt.Println("Got here! ", state.SYN_SENT)
			bytes, err := pkgUtils.Marshal(*c)
			if err != nil {
				fmt.Println("Err")
				return
			}

			err = sendTCPPacket(c.SourceIp, c.DestIp, c.SourcePort, c.DestPort,0,int16(tcpHdr.SeqNum+1), header.TCPFlagAck, bytes)
			if err != nil {
				fmt.Println("Err")
				return
			}
			return
		}
		//handle this in milestone 2
		fmt.Println("Got here!")
		return
	}

	// IF DOES NOT EXIST:
	// look at the table for the 4-tuple that it's receiving
	port := tcpHdr.DstPort
	fmt.Println("Port to check: " + strconv.FormatInt(int64(port), 10))
	listenConn, exists := listenerTable[int16(port)]
	if exists {
		fmt.Println("exists")
		listenConn.Chan <- c
	}
	// if found, go into the table, grab the channel that corresponds to the listener, send information

}

func VConnect(addr netip.Addr, port int16) (*pkgUtils.VTCPConn, error) {
	randomPort := GenerateUniquePort(addr, connectionTable)
	sourceIp, err := lookup.GetHostIp()
	if err != nil {
		return nil, err
	}

	c := &pkgUtils.VTCPConn{
		SourceIp:   sourceIp,
		SourcePort: int16(randomPort),
		DestIp:     addr,
		DestPort:   port,
	}

	bytes, err := pkgUtils.Marshal(*c)
	if err != nil {
		return nil, err
	}

	err = sendTCPPacket(sourceIp, addr, int16(randomPort), port,1,0, header.TCPFlagSyn, bytes)
	if err != nil {
		return nil, err
	}

	connectionTable[*c] = &TCPMetadata{
		TCB:        make([]byte, bufsize),
		isReceiver: false,
		LastSeen:   0,
		Next:       0,
		Head:       0,
		State:      state.SYN_SENT,
	}
	fourtupleOrder = append(fourtupleOrder, OrderInfo{0,c})

	return c, nil
}


func sendTCPPacket(srcIp, destIp netip.Addr, srcPort, destPort, Syn, Ack int16, flags uint8, data []byte) error {
	tcpHdr := header.TCPFields{
		SrcPort:       uint16(srcPort),
		DstPort:       uint16(destPort),
		SeqNum:        uint32(Syn),
		AckNum:        uint32(Ack),
		DataOffset:    20,
		Flags:         flags,
		WindowSize:    65535,
		Checksum:      0,
		UrgentPointer: 0,
	}

	checksum := iptcp_utils.ComputeTCPChecksum(&tcpHdr, srcIp, destIp, data)
	tcpHdr.Checksum = checksum

	tcpHeaderBytes := make(header.TCP, iptcp_utils.TcpHeaderLen)
	tcpHeaderBytes.Encode(&tcpHdr)

	packetBytes := append(tcpHeaderBytes, data...)

	IPheader, err := lookup.CreateHeader(destIp, srcIp, len(packetBytes), 6, 64)
	if err != nil {
		return fmt.Errorf("error creating IP header: %w", err)
	}

	if err := lookup.SendIP(destIp, 6, append(IPheader, packetBytes...)); err != nil {
		return fmt.Errorf("error sending IP packet: %w", err)
	}

	return nil
}

func GenerateUniquePort(addr netip.Addr, connectionTable map[pkgUtils.VTCPConn]*TCPMetadata) int16 {
	rand.Seed(time.Now().UnixNano())
	min := 1024
	max := 9998

	var randomPort int
	for {
		randomPort = rand.Intn(max-min+1) + min

		isPortInUse := false
		for conn := range connectionTable {
			if conn.SourceIp == addr && conn.SourcePort == int16(randomPort) {
				isPortInUse = true
				break
			}
		}

		if !isPortInUse {
			break
		}
	}

	return int16(randomPort)
}
