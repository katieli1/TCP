package tcp

import (
	"bufio"
	"fmt"
	buf "ip/pkg/buffer"
	"ip/pkg/iptcp_utils"
	"ip/pkg/lookup"
	"ip/pkg/pkgUtils"
	s "ip/pkg/send-buffer"
	state "ip/pkg/tcp_states"
	"math/rand"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/netstack/tcpip/header"
	//"github.com/google/netstack/tcpip/seqnum"
)

type TCPMetadata struct {
	sendBuf    s.SendBuf
	receiveBuf buf.Buffer
	Seq        int16
	Ack        int16
	Window     int16 // the other person's window size
	State      state.TCPState
}
type VAcceptInfo struct {
	Conn *pkgUtils.VTCPConn
	Ack  int16
	Seq  int16
}

type VListener struct {
	Port int16
	Chan chan (*VAcceptInfo)
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
	return &VListener{Port: port, Chan: make(chan *VAcceptInfo)}
}

func ACommand(port int16) {
	listenConn := VListen(port)
	listenerTable[port] = listenConn
	fourtupleOrder = append(fourtupleOrder, OrderInfo{port, nil})
	for {
		VAcceptInfo, ok := <-listenConn.Chan
		if !ok {
			fmt.Println("failed")
		}
		_, _ = listenConn.VAccept(*VAcceptInfo)
	}
}

func (*VListener) VAccept(vAcceptInfo VAcceptInfo) (*pkgUtils.VTCPConn, error) {
	fourTuple := *vAcceptInfo.Conn
	connectionTable[fourTuple] = &TCPMetadata{
		sendBuf:    s.SendBuf{Buf: buf.Buffer{Head: 0, Len: int16(bufsize), Arr: make([]byte, bufsize), WindowSize: int16(bufsize)}, UNA: 0},
		receiveBuf: buf.Buffer{Head: 0, Len: int16(bufsize), Arr: make([]byte, bufsize), WindowSize: int16(bufsize)},
		Seq:        vAcceptInfo.Ack,
		Ack:        vAcceptInfo.Seq + 1,
		State:      state.SYN_RECEIVED,
		Window:     int16(bufsize),
	}
	fourtupleOrder = append(fourtupleOrder, OrderInfo{0, &fourTuple}) // Assuming `fourTuple` is a value
	rand.Seed(time.Now().UnixNano())
	min := 1024
	max := 9998

	randomSeq := rand.Intn(max-min+1) + min
	err := sendTCPPacket(fourTuple.SourceIp, fourTuple.DestIp, fourTuple.SourcePort, fourTuple.DestPort, int16(randomSeq), vAcceptInfo.Seq+1, header.TCPFlagSyn|header.TCPFlagAck, nil, uint16(bufsize))
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
		if connection.State == state.SYN_RECEIVED {
			connection.State = state.ESTABLISHED
			return
		}
		connection.Ack = int16(tcpHdr.SeqNum)
		if connection.State == state.SYN_SENT {
			connection.State = state.ESTABLISHED
			connection.Seq = int16(tcpHdr.AckNum)
			connection.Ack = int16(tcpHdr.SeqNum + 1)
			err := sendTCPPacket(c.SourceIp, c.DestIp, c.SourcePort, c.DestPort, connection.Seq, connection.Ack, header.TCPFlagAck, nil, uint16(bufsize))
			if err != nil {
				fmt.Println("Err")
				return
			}
			return
		}
		//handle this in milestone 2
		//connection.LastSeen = int16(tcpHdr.AckNum)
		// TODO: send an ack here
		fmt.Println("updating window size")
		connection.Window = int16(tcpHdr.WindowSize)
		if len(tcpPayload) != 0 {
			connection.Seq = int16(tcpHdr.AckNum)
			fmt.Println("Window Size Callback 1: ", connection.receiveBuf.WindowSize)
			connection.receiveBuf.Write(tcpPayload)
			fmt.Println("Window Size Callback 2: ", connection.receiveBuf.WindowSize)
			// connection.receiveBuf.WindowSize -= int16(len(tcpPayload))
			fmt.Println("Window Size Callback 3: ", connection.receiveBuf.WindowSize)
			connection.Ack = int16(tcpHdr.SeqNum) + int16(len(tcpPayload))

			err := sendTCPPacket(c.SourceIp, c.DestIp, c.SourcePort, c.DestPort, connection.Seq, connection.Ack, header.TCPFlagAck, nil, uint16(connection.receiveBuf.WindowSize))
			if err != nil {
				fmt.Println("Err")
				return
			}
		} else {
			//update variables for ack
			//Todo, not use read but instead update the sender buffer with the new last send, next ....
			connection.sendBuf.Read(int16(tcpHdr.AckNum) - connection.Seq)
			connection.sendBuf.UpdateUNA(int16(tcpHdr.AckNum) - connection.Seq)
			connection.Seq = int16(tcpHdr.AckNum)

			// connection.sendBuf.WindowSize = int16(tcpHdr.WindowSize)
		}
		return
	}

	// IF DOES NOT EXIST:
	port := tcpHdr.DstPort
	listenConn, exists := listenerTable[int16(port)]
	if exists {
		listenConn.Chan <- &VAcceptInfo{Conn: c, Seq: int16(tcpHdr.SeqNum), Ack: int16(tcpHdr.AckNum)}
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

	rand.Seed(time.Now().UnixNano())
	min := 1024
	max := 9998

	randomSeq := rand.Intn(max-min+1) + min

	err = sendTCPPacket(sourceIp, addr, int16(randomPort), port, int16(randomSeq), 0, header.TCPFlagSyn, nil, uint16(bufsize))
	if err != nil {
		return nil, err
	}

	connectionTable[*c] = &TCPMetadata{
		sendBuf:    s.SendBuf{Buf: buf.Buffer{Head: 0, Len: int16(bufsize), Arr: make([]byte, bufsize), WindowSize: int16(bufsize)}, UNA: 0},
		receiveBuf: buf.Buffer{Head: 0, Len: int16(bufsize), Arr: make([]byte, bufsize), WindowSize: int16(bufsize)},
		State:      state.SYN_SENT,
		Window:     int16(bufsize),
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

	if metadata.Window == 0 {
		fmt.Println("Failed to send bc window is 0")
		return nil
	}

	if int16(len(bytesMessage)) > metadata.sendBuf.Buf.WindowSize {
		bytesMessage = bytesMessage[:metadata.sendBuf.Buf.WindowSize]
	}
	metadata.sendBuf.Write(bytesMessage)
	fmt.Println("WindowSize: ", metadata.sendBuf.Buf.WindowSize)
	// metadata.Ack = metadata.sendBuf.GetLastRead()
	//update sender buffer with the information we are sending and then deleting that when we get an ack
	err := sendTCPPacket(
		orderStruct.VConn.SourceIp,
		orderStruct.VConn.DestIp,
		orderStruct.VConn.SourcePort,
		orderStruct.VConn.DestPort,
		metadata.Seq,
		metadata.Ack,
		header.TCPFlagAck,
		bytesMessage,
		uint16(metadata.sendBuf.Buf.WindowSize),
	)

	if err != nil {
		return fmt.Errorf("error sending TCP packet: %w", err)
	}

	return nil
}

func VRead(entry int16, bytesToRead int16) ([]byte, error) {
	orderStruct := fourtupleOrder[entry]

	if orderStruct.VConn == nil {
		// Cannot send message to a listener entry
		return nil, fmt.Errorf("cannot send message: listener entry")
	}
	c := orderStruct.VConn

	metadata := connectionTable[*orderStruct.VConn]

	// wasFull := false
	// if metadata.receiveBuf.WindowSize == 0 {
	// 	wasFull = true
	// }
	dataRead := metadata.receiveBuf.Read(bytesToRead)
	if len(dataRead) != 0 { // was full but now it's not, so send an ack
		err := sendTCPPacket(c.SourceIp, c.DestIp, c.SourcePort, c.DestPort, metadata.Seq, metadata.Ack, header.TCPFlagAck, nil, uint16(metadata.receiveBuf.WindowSize))
		if err != nil {
			return nil, err
		}
	}
	// metadata.receiveBuf.WindowSize += int16(min(int16(len(dataRead)),metadata.receiveBuf.Len))

	// TODO: FIX
	// if len(metadata.TCB) < int(bytesToRead) {
	// 	return fmt.Errorf("not enough data in buffer to read %d bytes", bytesToRead)
	// }

	// fmt.Println("data as bytes: ", dataRead)
	// fmt.Printf("Read %d bytes: %s\n", bytesToRead, string(dataRead))

	//metadata.TCB = metadata.TCB[bytesToRead:]

	// connectionTable[*orderStruct.VConn] = metadata

	return dataRead, nil
}

func sendTCPPacket(srcIp, destIp netip.Addr, srcPort, destPort, Seq, Ack int16, flags uint8, data []byte, WindowSize uint16) error {

	tcpHdr := header.TCPFields{
		SrcPort:       uint16(srcPort),
		DstPort:       uint16(destPort),
		SeqNum:        uint32(Seq),
		AckNum:        uint32(Ack),
		DataOffset:    20,
		Flags:         flags,
		WindowSize:    WindowSize,
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

func min(a, b int16) int16 {
	if a < b {
		return a
	}
	return b
}
