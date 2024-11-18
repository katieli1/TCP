package tcp

import (
	"errors"
	"fmt"
	"io"
	buf "ip/pkg/buffer"
	"ip/pkg/iptcp_utils"
	"ip/pkg/lookup"
	s "ip/pkg/send-buffer"
	state "ip/pkg/tcp_states"
	"math/rand"
	"net/netip"
	"os"

	"time"

	"github.com/google/netstack/tcpip/header"
	//"github.com/google/netstack/tcpip/seqnum"
)

type TCPMetadata struct {
	sendBuf    s.SendBuf
	receiveBuf s.RecieveBuf
	Seq        int16
	Ack        int16
	Window     int16 // the other person's window size
	State      state.TCPState
	Chan       chan bool
}
type VTCPConn struct {
	SourceIp   netip.Addr
	SourcePort int16
	DestIp     netip.Addr
	DestPort   int16
}

type VAcceptInfo struct {
	Conn *VTCPConn
	Ack  int16
	Seq  int16
}

type VListener struct {
	Port int16
	Chan chan (*VAcceptInfo)
}
type OrderInfo struct {
	Port  int16
	VConn *VTCPConn
}

var fourtupleOrder []OrderInfo

var connectionTable = make(map[VTCPConn]*TCPMetadata)
var listenerTable = make(map[int16]*VListener)
var bufsize = 10
var sid = 0

func Initialize(fileName string) {
	go lookup.Initialize(fileName)
}

func Retransmit(conn *TCPMetadata, VConn *VTCPConn) {
	// for {
	// 	time.Sleep(1 * time.Second)
	// 	conn.sendBuf.QueueMutex.RLock()
	// 	for _, p := range conn.sendBuf.Queue {
	// 		err := sendTCPPacket(
	// 			VConn.SourceIp,
	// 			VConn.DestIp,
	// 			VConn.SourcePort,
	// 			VConn.DestPort,
	// 			p.Seq,
	// 			conn.Ack,
	// 			header.TCPFlagAck,
	// 			p.Data,
	// 			uint16(conn.receiveBuf.Buf.WindowSize),
	// 		)
	// 		if err != nil {
	// 			fmt.Println("Error sending packet during retransmission")
	// 		}
	// 	}
	// 	conn.sendBuf.QueueMutex.RUnlock()
	// }

}

func VListen(port int16) *VListener {
	return &VListener{Port: port, Chan: make(chan *VAcceptInfo)}
}

func (l *VListener) VAccept() (*VTCPConn, error) {
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
		sendBuf:    s.SendBuf{Buf: buf.Buffer{Head: 0, Len: int16(bufsize), Arr: make([]byte, bufsize), WindowSize: int16(bufsize)}, UNA: 0, Chan: make(chan int16), StartingSeq: randomSeq, Queue: make([]s.Packet, 0)},
		receiveBuf: s.RecieveBuf{Buf: buf.Buffer{Head: 0, Len: int16(bufsize), Arr: make([]byte, bufsize), WindowSize: int16(bufsize)}, Chan: make(chan int16)},
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
	go Retransmit(connectionTable[fourTuple], &fourTuple)

	return &fourTuple, nil
}

func Callback_TCP(msg []byte, source netip.Addr, dest netip.Addr, ttl int) {
	// fmt.Println("in callback tcp")
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

	c := &VTCPConn{
		SourceIp:   dest,
		SourcePort: int16(tcpHdr.DstPort),
		DestIp:     source,
		DestPort:   int16(tcpHdr.SrcPort),
	}

	// if ALREADY EXISTS, we are not receiving a VConnect. we should update the buffer in connection table

	connection, exists := connectionTable[*c]

	if exists {
		// fmt.Println("window size at start of callback ", connection.sendBuf.Buf.WindowSize)

		if tcpHdr.Flags == header.TCPFlagSyn|header.TCPFlagAck { // this is a packet sent by a VAccept
			connection.Chan <- true
		}
		//connection.Ack = int16(tcpHdr.SeqNum)

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
		//fmt.Println("updating window size")
		connection.Window = int16(tcpHdr.WindowSize)

		if tcpHdr.Flags == header.TCPFlagSyn { // this is a packet sent from a VConnect

			port := tcpHdr.DstPort
			listenConn, exists := listenerTable[int16(port)]
			if exists {
				listenConn.Chan <- &VAcceptInfo{Conn: c, Seq: int16(tcpHdr.SeqNum), Ack: int16(tcpHdr.AckNum)}
			}
		}
		// fmt.Println("header ack: ", tcpHdr.AckNum)
		// fmt.Println("connection seq: ", int(connection.Seq))
		// fmt.Println("starting seq: ", connection.sendBuf.StartingSeq)
		// if tcpHdr.AckNum != (uint32(connection.Seq))
		if len(tcpPayload) != 0 { // data packet
			//fmt.Println("callback is processing data packet")
			if len(tcpPayload) > int(connection.receiveBuf.Buf.WindowSize) {
				return
			}

			connection.Seq = int16(tcpHdr.AckNum)
			fmt.Println("tcp payload " + string(tcpPayload))
			// bytesCanBeRead := connection.receiveBuf.Buf.Len - connection.receiveBuf.Buf.WindowSize
			connection.receiveBuf.Buf.Write(tcpPayload) // TODO: handle case where size is bigger than window size
			// fmt.Println("ack before updating ", connection.Ack)
			// fmt.Println("payload len ", len(tcpPayload))
			connection.Ack = int16(tcpHdr.SeqNum) + int16(len(tcpPayload))
			//fmt.Println("ack after updating ", connection.Ack)
			// if bytesCanBeRead == 0 { // TODO: MAKE THIS NON-BLOCKING, PROBABLY FIX CONDITION
			// 	connection.receiveBuf.Chan <- 0
			// }
			windowSize := uint16(connection.receiveBuf.Buf.WindowSize)

			select {

			case bytesToRead := <-connection.receiveBuf.Chan:
				//windowSize += uint16(bytesToRead)
				bytesRead := uint16(min(bytesToRead, connection.receiveBuf.Buf.Len-connection.receiveBuf.Buf.WindowSize))
				windowSize = bytesRead + uint16(connection.receiveBuf.Buf.WindowSize)
				fmt.Println("bytes to read sent through channel. window size ", windowSize)
				fmt.Println("bytesRead ", bytesRead)
			default:
				// fmt.Println("channel not ready, no receiver waiting")
			}

			fmt.Println("sending callback")
			err := sendTCPPacket(c.SourceIp, c.DestIp, c.SourcePort, c.DestPort, connection.Seq, connection.Ack, header.TCPFlagAck, nil, windowSize)
			if err != nil {
				fmt.Println("Err")
				return
			}

		} else {
			// fmt.Println("callback is processing ACK packet")
			// fmt.Println("tcp header window size: ", tcpHdr.WindowSize)
			//update variables for ack
			//Todo, not use read but instead update the sender buffer with the new last send, next ....
			// connection.sendBuf.Read(int16(tcpHdr.AckNum) - connection.Seq)

			connection.sendBuf.UpdateUNA(int16(tcpHdr.AckNum))
			diff := tcpHdr.AckNum - uint32(connection.Seq)
			connection.Seq = int16(tcpHdr.AckNum)

			// fmt.Println("receiver window size in callback: ", tcpHdr.WindowSize)
			//connection.Window += int16(connection.sendBuf.UNA)
			//update := connection.sendBuf.Buf.WindowSize == 0
			connection.sendBuf.Buf.WindowSize += int16(diff)
			// fmt.Println("diff ", diff)
			// fmt.Println("updated window size ", connection.sendBuf.Buf.WindowSize)
			// if update {
			// 	// fmt.Println("sending to channel")
			// 	connection.sendBuf.Chan <- int16(connection.sendBuf.UNA)
			// }

			connection.sendBuf.QueueMutex.Lock()
			fmt.Println("contents of queue before removal ", connection.sendBuf.Queue)
			newQueue := connection.sendBuf.Queue[:0]
			for _, p := range connection.sendBuf.Queue {
				if len(p.Data)+int(p.Seq) != int(tcpHdr.AckNum) {
					newQueue = append(newQueue, p) // keep packets that are not the one currently being ACKed
				}
			}
			connection.sendBuf.Queue = newQueue
			fmt.Println("contents of queue after removal ", connection.sendBuf.Queue)

			connection.sendBuf.QueueMutex.Unlock()

			select {
			case connection.sendBuf.Chan <- int16(connection.sendBuf.UNA):
				// fmt.Println("sent through channel")
			default:
				// fmt.Println("channel not ready, no receiver waiting")
			}

			// fmt.Println("after")
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

	//fmt.Println("end of callback tcp")
}

func ZeroWindowProbing(VConn VTCPConn, toSend byte) { // toSend is a byteslice with one byte
	fmt.Println("zero window probing")
	metadata := connectionTable[VConn]
	for metadata.Window == 0 {

		err := sendTCPPacket(
			VConn.SourceIp,
			VConn.DestIp,
			VConn.SourcePort,
			VConn.DestPort,
			metadata.Seq,
			metadata.Ack,
			header.TCPFlagAck,
			[]byte{toSend},
			uint16(metadata.sendBuf.GetWindowSize()), // has to be our reciever's buffer
		)
		if err != nil {
			fmt.Println("error sending TCP packet: %w", err)
		}
		time.Sleep(1 * time.Second)
	}

	// don't need to add to queue because we've already gotten an ack if we break out of the for loop
}

func VConnect(addr netip.Addr, port int16) (*VTCPConn, error) {
	randomPort := GenerateUniquePort(addr, connectionTable)
	sourceIp, err := lookup.GetHostIp()
	if err != nil {
		return nil, err
	}

	c := &VTCPConn{
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

	// TODO: VConnect channel
	ch := make(chan bool)

	connectionTable[*c] = &TCPMetadata{
		sendBuf:    s.SendBuf{Buf: buf.Buffer{Head: 0, Len: int16(bufsize), Arr: make([]byte, bufsize), WindowSize: int16(bufsize)}, UNA: 0, Chan: make(chan int16), StartingSeq: randomSeq, Queue: make([]s.Packet, 0)},
		receiveBuf: s.RecieveBuf{Buf: buf.Buffer{Head: 0, Len: int16(bufsize), Arr: make([]byte, bufsize), WindowSize: int16(bufsize)}, Chan: make(chan int16)},
		State:      state.SYN_SENT,
		Window:     int16(bufsize),
		Chan:       ch,
	}

	fourtupleOrder = append(fourtupleOrder, OrderInfo{0, c})
	_, ok := <-ch
	if !ok {
		fmt.Println("failed")
	}
	go Retransmit(connectionTable[*c], c)

	return c, nil
}

func (VConn VTCPConn) VWrite(message string) error {
	metadata := connectionTable[VConn]

	bytesMessage := []byte(message)

	// if metadata.Window == 0 {
	// 	fmt.Println("Failed to send bc window is 0")
	// 	return nil
	// }

	// if int16(len(bytesMessage)) > metadata.sendBuf.Buf.WindowSize {
	// 	bytesMessage = bytesMessage[:metadata.sendBuf.Buf.WindowSize]
	// }
	//metadata.sendBuf.Write(bytesMessage)

	data := bytesMessage
	bytesToWrite := len(data)
	offset := 0
	// fmt.Println("bytes to write ", bytesToWrite)
	// fmt.Println("available space in send buf ", metadata.sendBuf.Buf.WindowSize)
	for bytesToWrite > 0 {
		if metadata.Window == 0 {
			metadata.sendBuf.Buf.Write(data[offset : offset+1])
			ZeroWindowProbing(VConn, data[offset])
			offset++
			bytesToWrite--
		}
		end := min(int16(offset+int(metadata.sendBuf.Buf.WindowSize)), int16(offset+(bytesToWrite)))

		if int(metadata.Window) < int(end)-offset {
			fmt.Println("truncating")
			end = int16(offset) + metadata.Window
		}

		metadata.sendBuf.Buf.Write(data[offset:end])

		// fmt.Println("WindowSize in vsend: ", metadata.sendBuf.Buf.WindowSize)
		fmt.Println("send buffer: ", metadata.sendBuf.Buf.Arr)

		dataToSend := metadata.sendBuf.GetDataToSend()

		// if int(metadata.Window) < len(metadata.sendBuf.GetDataToSend()) {
		// 	fmt.Println("truncating")
		// 	dataToSend = dataToSend[0:metadata.Window]
		// }
		fmt.Println("data to send ", dataToSend)

		err := sendTCPPacket(
			VConn.SourceIp,
			VConn.DestIp,
			VConn.SourcePort,
			VConn.DestPort,
			metadata.Seq,
			metadata.Ack,
			header.TCPFlagAck,
			dataToSend,
			uint16(metadata.receiveBuf.Buf.WindowSize),
		)
		metadata.sendBuf.QueueMutex.Lock()
		metadata.sendBuf.Queue = append(metadata.sendBuf.Queue, s.Packet{Seq: metadata.Seq, Data: dataToSend})
		metadata.sendBuf.QueueMutex.Unlock()

		if err != nil {
			return fmt.Errorf("error sending TCP packet: %w", err)
		}
		ok := true
		_, ok = <-metadata.sendBuf.Chan
		//fmt.Println("updated window size after channel ", metadata.sendBuf.Buf.WindowSize)
		bytesToWrite -= int(len(dataToSend))
		offset += int(len(dataToSend))
		//fmt.Println("after receiving from channel")
		if !ok {
			fmt.Println("error in sendbuf while loop")
		}
	}
	return nil
}

func (VConn VTCPConn) VRead(buffer []byte) error {
	//c := orderStruct.VConn

	metadata := connectionTable[VConn]

	//wasFull := metadata.receiveBuf.WindowSize == 0
	bytesToRead := int16(len(buffer))
	offset := 0
	// Read data into a temporary slice of the requested size
	//fmt.Println("len(buffer): ", int16(len(buffer)))
	for bytesToRead > 0 {

		bytesCanBeRead := metadata.receiveBuf.Buf.Len - metadata.receiveBuf.Buf.WindowSize
		if bytesCanBeRead == 0 {
			metadata.receiveBuf.Chan <- bytesCanBeRead
			bytesCanBeRead = metadata.receiveBuf.Buf.Len - metadata.receiveBuf.Buf.WindowSize
		}
		fmt.Println("bytesCanBeRead: ", bytesCanBeRead, " buf len", metadata.receiveBuf.Buf.Len, " window size ", metadata.receiveBuf.Buf.WindowSize)
		fmt.Println("bytes to Read: ", bytesToRead)
		dataRead := metadata.receiveBuf.Buf.Read(min(bytesToRead, bytesCanBeRead))

		copy(buffer[offset:], dataRead)
		bytesToRead -= int16(len(dataRead))
		offset += len(dataRead)
	}

	// err := sendTCPPacket(c.SourceIp, c.DestIp, c.SourcePort, c.DestPort, metadata.Seq, metadata.Ack, header.TCPFlagAck, nil, uint16(metadata.receiveBuf.Buf.WindowSize))
	// if err != nil {
	// 	fmt.Println("Err")
	// 	return err
	// }
	fmt.Println("left read loop")
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

func GenerateUniquePort(addr netip.Addr, connectionTable map[VTCPConn]*TCPMetadata) int16 {
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

func SendFiles(addr netip.Addr, port int16, filePath string) {
	// Establish connection
	conn, err := VConnect(addr, port)
	if err != nil {
		fmt.Printf("Failed to connect: %v\n", err)
		return
	}
	// defer conn.Close() // Ensure connection is closed

	// Open the file for reading
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("Failed to open file: %v\n", err)
		return
	}
	defer file.Close()

	// Create a buffer to read the file in chunks
	buffer := make([]byte, 1024) // 1 KB buffer size
	totalBytesSent := 0

	for {
		// Read a chunk from the file
		n, err := file.Read(buffer)
		if err != nil {
			if err == io.EOF {
				break // End of file reached
			}
			fmt.Printf("Error reading file: %v\n", err)
			return
		}

		// Send the chunk using VWrite
		err = conn.VWrite(string(buffer[:n]))
		if err != nil {
			fmt.Printf("Failed to send data: %v\n", err)
			return
		}
		totalBytesSent += n
	}

	fmt.Printf("File sent successfully. Total bytes sent: %d\n", totalBytesSent)
}

func ReceiveFiles(port int16, filePath string) {
	// Start listening on the specified port
	listenConn := VListen(port)
	listenerTable[port] = listenConn
	fourtupleOrder = append(fourtupleOrder, OrderInfo{port, nil})

	// Accept the incoming connection
	conn, err := listenConn.VAccept()
	if err != nil {
		fmt.Printf("Error accepting connection: %v\n", err)
		return
	}
	// defer conn.Close() // Ensure the connection is closed after receiving the file

	// Open the file for writing
	file, err := os.Create(filePath)
	if err != nil {
		fmt.Printf("Error creating file: %v\n", err)
		return
	}
	defer file.Close()

	// Create a buffer for reading data
	buffer := make([]byte, 199) // 1 KB buffer size
	totalBytesReceived := 0     // Track the total number of bytes received

	for {
		// Read data from the connection into the buffer
		err := conn.VRead(buffer)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break // End of data
			}
			fmt.Printf("Error reading data: %v\n", err)
			return
		}

		// Write the data to the file
		n, writeErr := file.Write(buffer)
		if writeErr != nil {
			fmt.Printf("Error writing to file: %v\n", writeErr)
			return
		}

		// Update total bytes received
		totalBytesReceived += n
		if (totalBytesReceived) == 199 {
			break
		}
		fmt.Printf("File received successfully. Total bytes received: %d\n", totalBytesReceived)
	}

	// Print the total bytes received
	fmt.Printf("File received successfully. Total bytes received: %d\n", totalBytesReceived)
}

func min(a, b int16) int16 {
	if a < b {
		return a
	}
	return b
}

// func VClose() {

// }
