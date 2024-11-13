package tcp

import (
	"fmt"
	buf "ip/pkg/buffer"
	"ip/pkg/iptcp_utils"
	"ip/pkg/lookup"
	"ip/pkg/pkgUtils"
	s "ip/pkg/send-buffer"
	state "ip/pkg/tcp_states"
	"math/rand"
	"net/netip"

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
	Chan       chan bool
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
}

func VListen(port int16) *VListener {
	return &VListener{Port: port, Chan: make(chan *VAcceptInfo)}
}

func (l *VListener) VAccept() (*pkgUtils.VTCPConn, error) {
	vAcceptInfo, ok := <-l.Chan
	if !ok {
		fmt.Println("failed")
	}
	fourTuple := *vAcceptInfo.Conn
	rand.Seed(time.Now().UnixNano())
	min := 1024
	max := 9998

	randomSeq := rand.Intn(max-min+1) + min
	connectionTable[fourTuple] = &TCPMetadata{
		sendBuf:    s.SendBuf{Buf: buf.Buffer{Head: 0, Len: int16(bufsize), Arr: make([]byte, bufsize), WindowSize: int16(bufsize)}, UNA: 0, Chan: make(chan int16), StartingSeq: randomSeq},
		receiveBuf: buf.Buffer{Head: 0, Len: int16(bufsize), Arr: make([]byte, bufsize), WindowSize: int16(bufsize)},
		Seq:        vAcceptInfo.Ack,
		Ack:        vAcceptInfo.Seq + 1,
		State:      state.SYN_RECEIVED,
		Window:     int16(bufsize),
	}
	fourtupleOrder = append(fourtupleOrder, OrderInfo{0, &fourTuple}) // Assuming `fourTuple` is a value

	err := sendTCPPacket(fourTuple.SourceIp, fourTuple.DestIp, fourTuple.SourcePort, fourTuple.DestPort, int16(randomSeq), vAcceptInfo.Seq+1, header.TCPFlagSyn|header.TCPFlagAck, nil, uint16(bufsize))
	if err != nil {
		return nil, err
	}

	connection := connectionTable[fourTuple]
	if connection.State == state.SYN_RECEIVED {
		connection.State = state.ESTABLISHED
	}

	return nil, nil
}

func Callback_TCP(msg []byte, source netip.Addr, dest netip.Addr, ttl int) {
	fmt.Println("in callback tcp")
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
		fmt.Println("exists")

		if tcpHdr.Flags == header.TCPFlagSyn|header.TCPFlagAck { // this is a packet sent by a VAccept
			fmt.Println("in callback case for vconnect")
			connection.Chan <- true
		}
		connection.Ack = int16(tcpHdr.SeqNum)

		if connection.State == state.SYN_SENT {
			fmt.Println("connection state is syn sent")
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

		if tcpHdr.Flags == header.TCPFlagSyn { // this is a packet sent from a VConnect

			port := tcpHdr.DstPort
			listenConn, exists := listenerTable[int16(port)]
			if exists {
				fmt.Println("sending to channel for VAccept ack")
				listenConn.Chan <- &VAcceptInfo{Conn: c, Seq: int16(tcpHdr.SeqNum), Ack: int16(tcpHdr.AckNum)}
			}
		}
		fmt.Println("header ack: ", tcpHdr.AckNum)
		fmt.Println("connection seq: ", int(connection.Seq))
		fmt.Println("starting seq: ", connection.sendBuf.StartingSeq)
		// if tcpHdr.AckNum != (uint32(connection.Seq))
		if len(tcpPayload) != 0 { // data packet
			connection.Seq = int16(tcpHdr.AckNum)
			fmt.Println("Window Size Callback 1: ", connection.receiveBuf.WindowSize)
			connection.receiveBuf.Write(tcpPayload) // TODO: handle case where size is bigger than window size
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
			connection.sendBuf.UpdateUNA(int16(tcpHdr.AckNum))
			connection.Seq = int16(tcpHdr.AckNum - 1)
			// fmt.Println("window size in ack: ", tcpHdr.WindowSize)
			fmt.Println("UNA in callback ", int16(connection.sendBuf.UNA))
			connection.Window += int16(connection.sendBuf.UNA)
			go func() {
				connection.sendBuf.Chan <- int16(connection.sendBuf.UNA)
			}()

			fmt.Println("after")
			// connection.sendBuf.WindowSize = int16(tcpHdr.WindowSize)
		}

	} else {
		// IF DOES NOT EXIST:
		port := tcpHdr.DstPort
		listenConn, exists := listenerTable[int16(port)]
		if exists {
			listenConn.Chan <- &VAcceptInfo{Conn: c, Seq: int16(tcpHdr.SeqNum), Ack: int16(tcpHdr.AckNum)}
		}

	}

	fmt.Println("end of callback tcp")
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
	fmt.Println("random seq ", randomSeq)

	err = sendTCPPacket(sourceIp, addr, int16(randomPort), port, int16(randomSeq), 0, header.TCPFlagSyn, nil, uint16(bufsize))
	if err != nil {
		return nil, err
	}

	// TODO: VConnect channel
	ch := make(chan bool)

	connectionTable[*c] = &TCPMetadata{
		sendBuf:    s.SendBuf{Buf: buf.Buffer{Head: 0, Len: int16(bufsize), Arr: make([]byte, bufsize), WindowSize: int16(bufsize)}, UNA: 0, Chan: make(chan int16), StartingSeq: randomSeq},
		receiveBuf: buf.Buffer{Head: 0, Len: int16(bufsize), Arr: make([]byte, bufsize), WindowSize: int16(bufsize)},
		State:      state.SYN_SENT,
		Window:     int16(bufsize),
		Chan:       ch,
	}

	fourtupleOrder = append(fourtupleOrder, OrderInfo{0, c})
	_, ok := <-ch
	if !ok {
		fmt.Println("failed")
	}
	fmt.Println("leaving VConnect")

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

	// if int16(len(bytesMessage)) > metadata.sendBuf.Buf.WindowSize {
	// 	bytesMessage = bytesMessage[:metadata.sendBuf.Buf.WindowSize]
	// }
	//metadata.sendBuf.Write(bytesMessage)

	data := bytesMessage
	bytesToWrite := len(data)
	offset := 0
	fmt.Println("bytes to write ", bytesToWrite)
	fmt.Println("available space in send buf ", metadata.sendBuf.Buf.WindowSize)
	for bytesToWrite > int(metadata.sendBuf.Buf.WindowSize) {
		metadata.sendBuf.Buf.Write(data[offset : offset+int(metadata.sendBuf.Buf.WindowSize)])
		bytesToWrite -= int(metadata.sendBuf.Buf.WindowSize)
		offset += int(metadata.sendBuf.Buf.WindowSize)
		fmt.Println("data to send ", metadata.sendBuf.Buf.Arr)

		err := sendTCPPacket(
			orderStruct.VConn.SourceIp,
			orderStruct.VConn.DestIp,
			orderStruct.VConn.SourcePort,
			orderStruct.VConn.DestPort,
			metadata.Seq,
			metadata.Ack,
			header.TCPFlagAck,
			metadata.sendBuf.Buf.Arr,
			uint16(metadata.sendBuf.Buf.WindowSize),
		)

		if err != nil {
			return fmt.Errorf("error sending TCP packet: %w", err)
		}
		fmt.Println("before receiving from channel")
		ok := true
		_, ok = <-metadata.sendBuf.Chan
		fmt.Println("after receiving from channel")
		if !ok {
			fmt.Println("error in sendbuf while loop")
		}
	}
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
	) // once these bytes are acked, they can exit the buffer and this loop can continue

	if err != nil {
		return fmt.Errorf("error sending TCP packet: %w", err)
	}

	return nil
}

func VRead(entry int16, buffer []byte) error {
	orderStruct := fourtupleOrder[entry]

	if orderStruct.VConn == nil {
		// Cannot send message to a listener entry
		return fmt.Errorf("cannot send message: listener entry")
	}
	c := orderStruct.VConn

	metadata := connectionTable[*orderStruct.VConn]

	//wasFull := metadata.receiveBuf.WindowSize == 0

	// Read data into a temporary slice of the requested size
	fmt.Println("len(buffer): ", int16(len(buffer)))
	dataRead := metadata.receiveBuf.Read(int16(len(buffer)))
	copy(buffer, dataRead) // Copy dataRead into the provided buffer

	// If the buffer was full and we've read data, send an ACK
	if len(dataRead) != 0 {
		err := sendTCPPacket(
			c.SourceIp, c.DestIp, c.SourcePort, c.DestPort,
			metadata.Seq, metadata.Ack, header.TCPFlagAck, nil,
			uint16(metadata.receiveBuf.WindowSize),
		)
		if err != nil {
			return err
		}
	}

	return nil
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
