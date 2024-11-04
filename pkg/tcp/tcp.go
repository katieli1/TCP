package tcp

import (
	"bufio"
	"fmt"
	buf "ip/pkg/buffer"
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

	"github.com/google/netstack/tcpip/header"
)

// TODO: fix seq / ack numbers (rename Syn), add second buffer (for receiver) to TCPMetadata, separate out buffer logic into library

type TCPMetadata struct {
	sendBuf    buf.Buffer
	receiveBuf buf.Buffer
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
	Port  int16
	VConn *pkgUtils.VTCPConn
}

var fourtupleOrder []OrderInfo

var connectionTable = make(map[pkgUtils.VTCPConn]*TCPMetadata)
var listenerTable = make(map[int16]*VListener)
var bufsize = 10
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
			if len(words) < 3 {
				fmt.Println("Usage: s <port> <message>")
				continue
			}
			entry, err := strconv.ParseInt(words[1], 10, 16)
			if err != nil {
				fmt.Printf("Invalid entry: %s\n", words[1])
				continue
			}

			message := strings.Join(words[2:], " ")

			VSend(int16(entry), message)
		} else if words[0] == "cl" { // close

		} else if words[0] == "ls" {
			fmt.Printf("%-10s %-15s %-10s %-15s %-10s %-10s\n", "SID", "LAddr", "LPort", "RAddr", "RPort", "Status")
			for index, v := range fourtupleOrder {
				if v.VConn != nil {
					if result, exists := connectionTable[*v.VConn]; exists {
						fmt.Printf("%-10d %-15s %-10s %-15s %-10s %-10s\n",
							index,
							v.VConn.SourceIp.String(),
							strconv.Itoa(int(v.VConn.SourcePort)),
							v.VConn.DestIp.String(),
							strconv.Itoa(int(v.VConn.DestPort)),
							result.State)
					}
				} else {
					fmt.Printf("%-10d %-15s %-10s %-15s %-10s %-10s\n",
						index,
						"0.0.0.0",
						strconv.Itoa(int(v.Port)),
						"0.0.0.0",
						"0",
						"LISTEN")
				}
			}
		} else if words[0] == "sf" {

		} else if words[0] == "rf" {

		} else if words[0] == "r" { // receive data on a socket
			if len(words) < 3 {
				fmt.Println("Usage: r <port> <bytes_to_read>")
				continue
			}

			port, err := strconv.ParseInt(words[1], 10, 16)
			if err != nil {
				fmt.Printf("Invalid port number: %s\n", words[1])
				continue
			}

			bytesToRead, err := strconv.ParseInt(words[2], 10, 16)
			if err != nil {
				fmt.Printf("Invalid bytes to read: %s\n", words[2])
				continue
			}

			VRead(int16(port), int16(bytesToRead))
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
	fourtupleOrder = append(fourtupleOrder, OrderInfo{port, nil})
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
		sendBuf:    buf.Buffer{Head: 0, Len: int16(bufsize), Arr: make([]byte, 0)},
		receiveBuf: buf.Buffer{Head: 0, Len: int16(bufsize), Arr: make([]byte, 0)},
		isReceiver: true,
		LastSeen:   0,
		Next:       0,
		Head:       0,
		State:      state.SYN_RECEIVED,
	}
	fourtupleOrder = append(fourtupleOrder, OrderInfo{0, &fourTuple}) // Assuming `fourTuple` is a value

	err := sendTCPPacket(fourTuple.SourceIp, fourTuple.DestIp, fourTuple.SourcePort, fourTuple.DestPort, 1, 1, header.TCPFlagSyn|header.TCPFlagAck, nil)
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

	tcpChecksumFromHeader := tcpHdr.Checksum
	tcpHdr.Checksum = 0

	tcpComputedChecksum := iptcp_utils.ComputeTCPChecksum(&tcpHdr, source, dest, tcpPayload)

	if tcpComputedChecksum != tcpChecksumFromHeader {
		fmt.Println("Error: bad checksum :(")
	}

	c := &pkgUtils.VTCPConn{
		SourceIp:   dest,
		SourcePort: int16(tcpHdr.DstPort),
		DestIp:     source,
		DestPort:   int16(tcpHdr.SrcPort),
	}

	// if ALREADY EXISTS, we are not receiving a VConnect. we should update the buffer in connection table

	connection, exists := connectionTable[*c]

	if exists {
		fmt.Println("head at start of callback: ", connection.Head)
		if connection.State == state.SYN_RECEIVED {
			connection.State = state.ESTABLISHED
			return
		}
		if connection.State == state.SYN_SENT {
			connection.State = state.ESTABLISHED

			err := sendTCPPacket(c.SourceIp, c.DestIp, c.SourcePort, c.DestPort, 2, 3, header.TCPFlagAck, nil)
			if err != nil {
				fmt.Println("Err")
				return
			}
			return
		}
		//handle this in milestone 2
		connection.LastSeen = int16(tcpHdr.AckNum)

		connection.receiveBuf.Write(tcpPayload)
		// detect wraparound
		// if connection.Head+int16(len(tcpPayload)) > int16(bufsize) { // yes wraparound
		// 	fmt.Println("wraparoudn in callback")
		// 	secondChunkSize := connection.Head + int16(len(tcpPayload)) - int16(bufsize)
		// 	firstChunkSize := int16(bufsize) - connection.Head
		// 	connection.TCB = append(connection.TCB, tcpPayload[:firstChunkSize]...)
		// 	copy(connection.TCB[:secondChunkSize], tcpPayload[firstChunkSize:])

		// } else { // no wraparaound
		// 	fmt.Println("no wrap in callback")
		// 	connection.TCB = append(connection.TCB, tcpPayload...)
		// }

		// fmt.Println("buffer in callback: ", connection.TCB)
		return
	}

	// IF DOES NOT EXIST:
	port := tcpHdr.DstPort
	listenConn, exists := listenerTable[int16(port)]
	if exists {
		fmt.Println("exists")
		listenConn.Chan <- c
	}
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

	err = sendTCPPacket(sourceIp, addr, int16(randomPort), port, 1, 0, header.TCPFlagSyn, nil)
	if err != nil {
		return nil, err
	}

	connectionTable[*c] = &TCPMetadata{
		sendBuf:    buf.Buffer{Head: 0, Len: int16(bufsize), Arr: make([]byte, 0)},
		receiveBuf: buf.Buffer{Head: 0, Len: int16(bufsize), Arr: make([]byte, 0)},
		isReceiver: false,
		LastSeen:   0,
		Next:       0,
		Head:       0,
		State:      state.SYN_SENT,
	}
	fourtupleOrder = append(fourtupleOrder, OrderInfo{0, c})

	return c, nil
}

func VSend(entry int16, message string) error {
	orderStruct := fourtupleOrder[entry]

	if orderStruct.VConn == nil {
		// Cannot send message to a listener entry
		return fmt.Errorf("cannot send message: listener entry")
	}

	metadata := connectionTable[*orderStruct.VConn]

	bytesMessage := []byte(message)
	metadata.Next += int16(len(message))

	seqNum := metadata.Next
	fmt.Println("seqnum ", seqNum)
	ackNum := metadata.LastSeen

	err := sendTCPPacket(
		orderStruct.VConn.SourceIp,
		orderStruct.VConn.DestIp,
		orderStruct.VConn.SourcePort,
		orderStruct.VConn.DestPort,
		seqNum,
		ackNum,
		header.TCPFlagSyn|header.TCPFlagAck,
		bytesMessage,
	)

	if err != nil {
		return fmt.Errorf("error sending TCP packet: %w", err)
	}

	return nil
}

func VRead(entry int16, bytesToRead int16) error {
	orderStruct := fourtupleOrder[entry]

	if orderStruct.VConn == nil {
		// Cannot send message to a listener entry
		return fmt.Errorf("cannot send message: listener entry")
	}

	metadata := connectionTable[*orderStruct.VConn]

	// TODO: FIX
	// if len(metadata.TCB) < int(bytesToRead) {
	// 	return fmt.Errorf("not enough data in buffer to read %d bytes", bytesToRead)
	// }

	dataRead := metadata.receiveBuf.Read(bytesToRead)
	// var dataToRead []byte
	// // detect wraparound; potentially off by 1
	// if metadata.Head+bytesToRead <= int16(bufsize) { // there is no wraparound
	// 	fmt.Println("no wraparound. metadata head: ", metadata.Head)
	// 	fmt.Println("bytes to read ", bytesToRead)
	// 	end := metadata.Head + bytesToRead
	// 	dataToRead = metadata.TCB[metadata.Head:end]
	// } else { // there is a wraparound
	// 	fmt.Println("wraparound")
	// 	dataToRead = metadata.TCB[metadata.Head:] // first chunk: head to end of buffer
	// 	diff := metadata.Head + bytesToRead - int16(bufsize)
	// 	dataToRead = append(dataToRead, metadata.TCB[:diff]...) // append second chunk (starting from beginning of buffer)
	// }

	fmt.Println("data as bytes: ", dataRead)
	fmt.Printf("Read %d bytes: %s\n", bytesToRead, string(dataRead))

	//metadata.TCB = metadata.TCB[bytesToRead:]
	metadata.Head += bytesToRead

	metadata.Head = metadata.Head % int16(bufsize)

	// connectionTable[*orderStruct.VConn] = metadata

	return nil
}

func sendTCPPacket(srcIp, destIp netip.Addr, srcPort, destPort, Syn, Ack int16, flags uint8, data []byte) error {
	// fmt.Println("received seq ", Syn)
	// fmt.Println("casted seq ", uint32(Syn))
	// fmt.Println("received ack ", Ack)
	// fmt.Println("received ack ", uint32(Ack))

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
