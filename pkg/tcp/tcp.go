package tcp

//rf output 9999
//sf smallTest 10.1.0.2 9999
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
	sendBuf         s.SendBuf
	receiveBuf      s.RecieveBuf
	Seq             int16
	Ack             int16
	LastRecievedAck int16
	Window          int16 // the other person's window size
	State           state.TCPState
	Chan            chan bool
	OutOfOrder      map[int16][]byte
}
type VTCPConn struct {
	SourceIp   netip.Addr
	SourcePort int16
	DestIp     netip.Addr
	DestPort   int16
}

type VAcceptInfo struct {
	Conn  *VTCPConn
	Ack   int16
	Seq   int16
	Flags uint8
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

func Initialize(fileName string) {
	go lookup.Initialize(fileName)
}

func Retransmit(conn *TCPMetadata, VConn *VTCPConn) {
	for {
		time.Sleep(1 * time.Second)
		conn.sendBuf.QueueMutex.RLock()
		for _, p := range conn.sendBuf.Queue {
			if p.Seq >= conn.sendBuf.UNA {
				err := sendTCPPacket(
					VConn.SourceIp,
					VConn.DestIp,
					VConn.SourcePort,
					VConn.DestPort,
					p.Seq,
					conn.Ack,
					header.TCPFlagAck,
					p.Data,
					uint16(conn.receiveBuf.Buf.WindowSize),
				)
				if err != nil {
					fmt.Println("Error sending packet during retransmission")
				}
			}
		}
		conn.sendBuf.QueueMutex.RUnlock()
	}
}

func VListen(port int16) *VListener {
	return &VListener{Port: port, Chan: make(chan *VAcceptInfo)}
}

func (l *VListener) VAccept() (*VTCPConn, error) {
	vAcceptInfo, ok := <-l.Chan
	if !ok {
		fmt.Println("failed: channel closed")
		return nil, fmt.Errorf("failed: channel closed")
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
		OutOfOrder: make(map[int16][]byte),

	}
	fourtupleOrder = append(fourtupleOrder, OrderInfo{0, &fourTuple})

	// Send the initial SYN-ACK
	err := sendTCPPacket(fourTuple.SourceIp, fourTuple.DestIp, fourTuple.SourcePort, fourTuple.DestPort, int16(randomSeq), vAcceptInfo.Seq+1, header.TCPFlagSyn|header.TCPFlagAck, nil, uint16(bufsize))
	if err != nil {
		return nil, err
	}

	// Define retransmission timeout and retry limit
	const retransmitTimeout = 2 * time.Second
	const maxRetries = 5 // Max retries before failing
	retryCount := 0

	for {
		select {
		case response, ok := <-l.Chan:


			if !ok {
				fmt.Println("failed: channel closed")
				return nil, fmt.Errorf("failed: channel closed")
			}

			// Handle SYN packet from the other side
			if response.Flags == header.TCPFlagSyn {
				err := sendTCPPacket(fourTuple.SourceIp, fourTuple.DestIp, fourTuple.SourcePort, fourTuple.DestPort, int16(randomSeq), vAcceptInfo.Seq+1, header.TCPFlagSyn|header.TCPFlagAck, nil, uint16(bufsize))
				if err != nil {
					return nil, fmt.Errorf("error sending SYN-ACK: %v", err)
				}
				continue
			}

			// Process valid response and establish connection
			connection := connectionTable[fourTuple]
			if connection.State == state.SYN_RECEIVED {
				connection.State = state.ESTABLISHED
				connection.Seq = int16(randomSeq)

				// Connection established, stop retransmitting
				go Retransmit(connectionTable[fourTuple], &fourTuple)
				return &fourTuple, nil
			}

		case <-time.After(retransmitTimeout): // Timer expired, retransmit
			if retryCount >= maxRetries {
				// Retry limit exceeded, abort connection attempt
				fmt.Println("Max retries reached, closing connection.")
				return nil, fmt.Errorf("connection attempt failed after %d retries", maxRetries)
			}


			// Retransmit the SYN-ACK if we haven't received a valid response
			fmt.Println("Retransmitting SYN-ACK... Retry count:", retryCount+1)

			err := sendTCPPacket(fourTuple.SourceIp, fourTuple.DestIp, fourTuple.SourcePort, fourTuple.DestPort, int16(randomSeq), vAcceptInfo.Seq+1, header.TCPFlagSyn|header.TCPFlagAck, nil, uint16(bufsize))
			if err != nil {
				return nil, fmt.Errorf("error retransmitting SYN-ACK: %v", err)
			}

			// Increment retry count
			retryCount++
		}
	}
}

func Callback_TCP(msg []byte, source netip.Addr, dest netip.Addr, ttl int) {
	// Parse the TCP header into a struct
	tcpHeaderAndData := []byte(msg)
	tcpHdr := iptcp_utils.ParseTCPHeader(tcpHeaderAndData)

	// Get the payload
	tcpPayload := tcpHeaderAndData[tcpHdr.DataOffset:]

	tcpChecksumFromHeader := tcpHdr.Checksum
	tcpHdr.Checksum = 0
	tcpComputedChecksum := iptcp_utils.ComputeTCPChecksum(&tcpHdr, source, dest, tcpPayload)

	if tcpComputedChecksum != tcpChecksumFromHeader {
		fmt.Println("Error: bad checksum :(")
		return
	}

	c := &VTCPConn{
		SourceIp:   dest,
		SourcePort: int16(tcpHdr.DstPort),
		DestIp:     source,
		DestPort:   int16(tcpHdr.SrcPort),
	}

	// Check if connection exists
	connection, exists := connectionTable[*c]

	if exists {
		connection.Window = int16(tcpHdr.WindowSize)

		if tcpHdr.Flags == header.TCPFlagSyn|header.TCPFlagAck { // Packet from VAccept to unblock VConn
			connection.Seq = int16(tcpHdr.AckNum)
			connection.Ack = int16(tcpHdr.SeqNum + 1)
			connection.LastRecievedAck = int16(tcpHdr.AckNum)
			connection.Chan <- true
			return
		}

		if tcpHdr.Flags == header.TCPFlagFin && connection.State != state.FIN_WAIT_2 { // we are receiving a fin for the first time

			connection.State = state.CLOSE_WAIT
			err := sendTCPPacket(c.SourceIp, c.DestIp, c.SourcePort, c.DestPort, connection.Seq, connection.Ack, header.TCPFlagAck, nil, uint16(connection.receiveBuf.Buf.WindowSize))
			if err != nil {
				fmt.Println("Err")

			}
			return

		}

		if tcpHdr.Flags == header.TCPFlagFin && connection.State == state.FIN_WAIT_2 { // we initiated the FIN
			connection.State = state.TIME_WAIT
			err := sendTCPPacket(c.SourceIp, c.DestIp, c.SourcePort, c.DestPort, connection.Seq, connection.Ack, header.TCPFlagAck, nil, uint16(connection.receiveBuf.Buf.WindowSize))
			if err != nil {
				fmt.Println("Err")
			}
			// wait 2 min, then delete TCB and set state to closed
			time.Sleep(2 * time.Minute)
			connection.State = state.CLOSED
			delete(connectionTable, *c)
			return
		}


		if connection.State == state.LAST_ACK {
			connection.State = state.CLOSED
			// delete TCB
			delete(connectionTable, *c)
			return
		}

		if connection.State == state.FIN_WAIT_1 {
			connection.State = state.FIN_WAIT_2
			return
		}

		if connection.State == state.SYN_RECEIVED { // Packet from VConnect to unblock VAccept
			UnblockVAccept(c, &tcpHdr)
		}

		// Handle data packet
		if len(tcpPayload) != 0 {
			// fmt.Println("CONN.SEQ ", connection.Seq)
			if len(tcpPayload) > int(connection.receiveBuf.Buf.WindowSize) {
				return
			}
			windowSize := uint16(connection.receiveBuf.Buf.WindowSize)
			// fmt.Println("Paquet seq ", tcpHdr.SeqNum, " connection Ack ", connection.Ack)
			if tcpHdr.SeqNum == uint32(connection.Ack) { // In-order packet
				fmt.Println("data: ", string(tcpPayload))
				connection.receiveBuf.Buf.Write(tcpPayload) // Write directly to the buffer
				connection.Ack += int16(len(tcpPayload))  // Advance the acknowledgment number
				windowSize -= uint16(len(tcpPayload))  

				// Process buffered out-of-order packets
				for {
					nextPayload, exists := connection.OutOfOrder[connection.Ack]
					if !exists || len(nextPayload) > int(connection.receiveBuf.Buf.WindowSize) {
						break
					}
					delete(connection.OutOfOrder, connection.Ack)   // Remove from the out-of-order map
					connection.receiveBuf.Buf.Write(nextPayload)    // Write the buffered payload
					connection.Ack += int16(len(nextPayload))      // Update acknowledgment number
					windowSize -= uint16(len(nextPayload))          // Update window size
				}

				// Unblock read operations
				select {
				case connection.receiveBuf.Chan <- int16(connection.receiveBuf.Buf.WindowSize):
				default:
				}
			} else if tcpHdr.SeqNum > uint32(connection.Ack) { // Out-of-order packet
				fmt.Println("HEre")
				connection.OutOfOrder[int16(tcpHdr.SeqNum)] = tcpPayload
			}

			// Advertise updated window size

			err := sendTCPPacket(c.SourceIp, c.DestIp, c.SourcePort, c.DestPort, connection.Seq, connection.Ack, header.TCPFlagAck, nil, windowSize)
			if err != nil {
				fmt.Println("Error sending ACK:", err)
				return
			}

		} else { // No payload (ACK or pure control packet)
			//update this logic

			// if tcpHdr.AckNum <= uint32(connection.Seq){

			connection.sendBuf.QueueMutex.Lock()
			newQueue := connection.sendBuf.Queue[:0]
			newBytesAcked := false
			for _, p := range connection.sendBuf.Queue {
				if len(p.Data)+int(p.Seq) > int(tcpHdr.AckNum) {
					newQueue = append(newQueue, p) // Keep packets not yet ACKed
				}else{
					newBytesAcked = true
				}
			}
			connection.sendBuf.Queue = newQueue
			connection.sendBuf.QueueMutex.Unlock()
			if newBytesAcked {
				connection.sendBuf.UpdateUNA(int16(tcpHdr.AckNum))
				diff := tcpHdr.AckNum - uint32(connection.LastRecievedAck)
				connection.LastRecievedAck = int16(tcpHdr.AckNum)
				connection.sendBuf.Buf.WindowSize += int16(diff)
				connection.Window = int16(tcpHdr.WindowSize)
				select {
				case connection.sendBuf.Chan <- int16(connection.sendBuf.UNA):
				default:
				}
			}
			// }
		}

	} else { // No existing connection

		UnblockVAccept(c, &tcpHdr)
	}
}

// func deleteTCB(c *VTCPConn) {
// 	connectionTable[]

// }

func UnblockVAccept(c *VTCPConn, tcpHdr *header.TCPFields) {
	port := tcpHdr.DstPort
	listenConn, exists := listenerTable[int16(port)]
	if exists {
		listenConn.Chan <- &VAcceptInfo{
			Conn:  c,
			Seq:   int16(tcpHdr.SeqNum),
			Ack:   int16(tcpHdr.AckNum),
			Flags: tcpHdr.Flags,
		}
	}
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

	// Send the initial SYN packet
	err = sendTCPPacket(sourceIp, addr, int16(randomPort), port, int16(randomSeq), 0, header.TCPFlagSyn, nil, uint16(bufsize))
	if err != nil {
		return nil, err
	}

	// Channel for response handling
	ch := make(chan bool)

	// Add entry to connectionTable
	connectionTable[*c] = &TCPMetadata{
		sendBuf:    s.SendBuf{Buf: buf.Buffer{Head: 0, Len: int16(bufsize), Arr: make([]byte, bufsize), WindowSize: int16(bufsize)}, UNA: 0, Chan: make(chan int16), StartingSeq: randomSeq, Queue: make([]s.Packet, 0)},
		receiveBuf: s.RecieveBuf{Buf: buf.Buffer{Head: 0, Len: int16(bufsize), Arr: make([]byte, bufsize), WindowSize: int16(bufsize)}, Chan: make(chan int16)},
		State:      state.SYN_SENT,
		Window:     int16(bufsize),
		Chan:       ch,
		OutOfOrder: make(map[int16][]byte),
	}

	fourtupleOrder = append(fourtupleOrder, OrderInfo{0, c})

	// Retransmission timeout duration and retry limit
	const retransmitTimeout = 3 * time.Second
	const maxRetries = 5 // Max number of retransmission attempts
	retryCount := 0

	for {
		select {
		case _, ok := <-ch:
			if !ok {
				fmt.Println("failed: channel closed")
				return nil, fmt.Errorf("failed: channel closed")
			}

			// Process the connection and send the ACK packet
			connection := connectionTable[*c]
			connection.State = state.ESTABLISHED

			err := sendTCPPacket(c.SourceIp, c.DestIp, c.SourcePort, c.DestPort, connection.Seq, connection.Ack, header.TCPFlagAck, nil, uint16(bufsize))
			if err != nil {
				fmt.Println("Error sending ACK:", err)
				return nil, err
			}
			go Retransmit(connectionTable[*c], c)
			// Return the connection information after sending the ACK
			return c, nil

		case <-time.After(retransmitTimeout): // Timer expired, retransmit the SYN packet
			if retryCount >= maxRetries {
				// Retry limit exceeded, abort connection attempt
				fmt.Println("Max retries reached, closing connection.")
				return nil, fmt.Errorf("connection attempt failed after %d retries", maxRetries)
			}

			// Retransmit the SYN packet if no valid response was received
			fmt.Println("Retransmitting SYN packet... Retry count:", retryCount+1)
			err := sendTCPPacket(sourceIp, addr, int16(randomPort), port, int16(randomSeq), 0, header.TCPFlagSyn, nil, uint16(bufsize))
			if err != nil {
				fmt.Println("Error retransmitting SYN:", err)
				return nil, err
			}

			// Increment retry count
			retryCount++
		}
	}
}

func (VConn VTCPConn) VWrite(message string) error {

	metadata := connectionTable[VConn]
	if metadata.State != state.ESTABLISHED {
		return errors.New("connection state is not established")
	}

	bytesMessage := []byte(message)

	data := bytesMessage
	bytesToWrite := len(data)
	offset := 0

	for bytesToWrite > 0 {
		if metadata.Window == 0 {
			metadata.sendBuf.Buf.Write(data[offset : offset+1])
			ZeroWindowProbing(VConn, data[offset])
			metadata.Seq += 1
			offset++
			bytesToWrite--
			metadata.Window -= 1
		}
		end := min(int16(offset+int(metadata.sendBuf.Buf.WindowSize)), int16(offset+(bytesToWrite)))
		end = min(end,int16(offset)+5) //HERE SHOULD BE 1024
		// fmt.Println("WindowSize in Write:", metadata.Window)
		if int(metadata.Window) < int(end)-offset {
			end = int16(offset) + metadata.Window
		}
		fmt.Println("end: ", end, " offset: ", offset)
		metadata.sendBuf.Buf.Write(data[offset:end])

		dataToSend := metadata.sendBuf.GetDataToSend(end-int16(offset))
		fmt.Println("data to send:", string(dataToSend))
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

		metadata.Seq += end - int16(offset)
		metadata.Window -= end - int16(offset)

		if err != nil {
			return fmt.Errorf("error sending TCP packet: %w", err)
		}
		ok := true
		// fmt.Println("before Here")
		if metadata.sendBuf.Buf.WindowSize == 0{
			_, ok = <-metadata.sendBuf.Chan
		}
		// fmt.Println("Here")
		bytesToWrite -= int(len(dataToSend))
		offset += int(len(dataToSend))
		if !ok {
			fmt.Println("error in sendbuf while loop")
		}
	}
	return nil
}

func (VConn VTCPConn) VRead(buffer []byte) (int16, error) {
	//c := orderStruct.VConn

	metadata := connectionTable[VConn]

	bytesToRead := int16(len(buffer))
	offset := 0
	// for bytesToRead > 0 {

	bytesCanBeRead := metadata.receiveBuf.Buf.Len - metadata.receiveBuf.Buf.WindowSize
	if bytesCanBeRead == 0 {
		<-metadata.receiveBuf.Chan

		bytesCanBeRead = metadata.receiveBuf.Buf.Len - metadata.receiveBuf.Buf.WindowSize
	}
	dataRead := metadata.receiveBuf.Buf.Read(min(bytesToRead, bytesCanBeRead))

	copy(buffer[offset:], dataRead)
	bytesToRead -= int16(len(dataRead))
	offset += len(dataRead)
	// }

	return int16(len(dataRead)), nil
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
		readBytes, err := conn.VRead(buffer)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break // End of data
			}
			fmt.Printf("Error reading data: %v\n", err)
			return
		}

		if readBytes == 0 {
			break
		}

		// Write the data to the file
		n, writeErr := file.Write(buffer[:readBytes])
		if writeErr != nil {
			fmt.Printf("Error writing to file: %v\n", writeErr)
			return
		}

		// for now this is fine but we need to stop the loop with FIN flag
		totalBytesReceived += n
		if (totalBytesReceived) >= 3064 {

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

func (c *VListener) VClose() error {
	fmt.Println("c: ", c)
	fmt.Println("c.Port: ", c.Port)
	_, exists := listenerTable[c.Port]
	if !exists {
		return errors.New("Listen socket does not exist")
	} else {
		index := -1
		for i, v := range fourtupleOrder {
			if v.Port == c.Port {
				index = i
				break
			}
		}

		// Check if the item was found
		if index == -1 {
			return errors.New("not found")
		}

		// Remove the item by slicing
		fourtupleOrder = append(fourtupleOrder[:index], fourtupleOrder[index+1:]...)
		delete(listenerTable, c.Port)
	}
	return nil
}

func (c *VTCPConn) VClose() error {
	metadata := connectionTable[*c]

	err := sendTCPPacket(c.SourceIp,
		c.DestIp,
		c.SourcePort,
		c.DestPort,
		metadata.Seq,
		metadata.Ack,
		header.TCPFlagFin,
		nil,
		uint16(metadata.receiveBuf.Buf.WindowSize))
	if err != nil {
		return err
	}
	if metadata.State != state.CLOSE_WAIT {
		metadata.State = state.FIN_WAIT_1
	} else {
		metadata.State = state.LAST_ACK
	}


	return nil
}
