package tcp

import (
	"github.com/google/netstack/tcpip/header"
	"bufio"
	"fmt"
	"ip/pkg/iptcp_utils"
	"ip/pkg/lookup"
	"ip/pkg/pkgUtils"
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
}
type VListener struct {
	Port int16
	Chan chan (*pkgUtils.VTCPConn)
}

var connectionTable = make(map[pkgUtils.VTCPConn]TCPMetadata)
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
			fmt.Println("SID       LAddr       LPort       RAddr       RPort       Status")
			for port := range listenerTable {
				fmt.Println("Port: ", strconv.FormatInt(int64(port), 10))
			}
			for conn := range connectionTable {
				fmt.Println("Source Port: ", strconv.FormatInt(int64(conn.SourcePort), 10))
				fmt.Println("Destination Port: ", strconv.FormatInt(int64(conn.DestPort), 10))
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

	for {
		fourTuple, ok:= <-listenConn.Chan
		if !ok {
			fmt.Println("failed")
		}
		fmt.Println("send accept now")
		clientConn, err := listenConn.VAccept(*fourTuple)
				fmt.Println("send accept now",clientConn,err)
	}
}

func (*VListener) VAccept(fourTuple pkgUtils.VTCPConn) (*pkgUtils.VTCPConn, error) {
	connectionTable[fourTuple] = TCPMetadata{
		isReceiver: false,
		LastSeen:   0,
		Next:       0,
		Head:       0,
	}

	//sending ACK
	bytes := []
	IPheader, err := lookup.CreateHeader(addr, sourceIp, len(bytes), 6, 64)
	if err != nil {
		fmt.Println("error creating IP header")
	}


	tcpHdr := header.TCPFields{
		SrcPort:       uint16(randomPort),
		DstPort:       uint16(port),
		SeqNum:        1,
		AckNum:        1,
		DataOffset:    20,
		Flags:         header.TCPFlagSyn | header.TCPFlagAck,
		WindowSize:    65535,
		Checksum:      0,
		UrgentPointer: 0,
	}

	checksum := iptcp_utils.ComputeTCPChecksum(&tcpHdr, sourceIp, addr, bytes)
	tcpHdr.Checksum = checksum

	// Serialize the TCP header
	tcpHeaderBytes := make(header.TCP, iptcp_utils.TcpHeaderLen)
	tcpHeaderBytes.Encode(&tcpHdr)

	lookup.SendIP(addr, 6, append(append(IPheader, tcpHeaderBytes...), bytes...))
	return nil, nil
}

func Callback_TCP(msg string, source netip.Addr, dest netip.Addr, ttl int) {
	fmt.Println("callback tcp")
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

	// if ALREADY EXISTS, we are not receiving a VConnect. we should update the buffer in connection table

	entryValue := connectionTable[fourTuple]
	if entryValue != nil {
		//handle this in milestone 2
		return
	}

	
	// IF DOES NOT EXIST:
	// look at the table for the 4-tuple that it's receiving
	port := tcpHdr.DstPort
	fmt.Println("Port to check: " + strconv.FormatInt(int64(port), 10))
	listenConn, exists := listenerTable[int16(port)]
	if exists {
		fmt.Println("exists")
		listenConn.Chan <- fourTuple
	}
	// if found, go into the table, grab the channel that corresponds to the listener, send information

}
func VConnect(addr netip.Addr, port int16) (*pkgUtils.VTCPConn, error) {
	// create random source port
	rand.Seed(time.Now().UnixNano())
	min := 1024
	max := 65535

	randomPort := rand.Intn(max-min+1) + min // TODO: make sure not already in use

	sourceIp, err := lookup.GetHostIp()
	if err != nil {
		return nil, err
	}
	c := &pkgUtils.VTCPConn{ // set source addr by using getter
		SourceIp:   sourceIp,
		SourcePort: int16(randomPort),
		DestIp:     addr,
		DestPort:   port,
	}

	bytes, err := pkgUtils.Marshal(*c)
	if err != nil {
		return nil, err
	}

	IPheader, err := lookup.CreateHeader(addr, sourceIp, len(bytes), 6, 64)
	if err != nil {
		fmt.Println("error creating IP header")
	}


	tcpHdr := header.TCPFields{
		SrcPort:       uint16(randomPort),
		DstPort:       uint16(port),
		SeqNum:        1,
		AckNum:        1,
		DataOffset:    20,
		Flags:         header.TCPFlagSyn | header.TCPFlagAck,
		WindowSize:    65535,
		Checksum:      0,
		UrgentPointer: 0,
	}

	checksum := iptcp_utils.ComputeTCPChecksum(&tcpHdr, sourceIp, addr, bytes)
	tcpHdr.Checksum = checksum

	// Serialize the TCP header
	tcpHeaderBytes := make(header.TCP, iptcp_utils.TcpHeaderLen)
	tcpHeaderBytes.Encode(&tcpHdr)


	lookup.SendIP(addr, 6, append(append(IPheader, tcpHeaderBytes...), bytes...))
	connectionTable[*c] = TCPMetadata{
		TCB:        make([]byte, bufsize),
		isReceiver: false,
		LastSeen:   0,
		Next:       0,
		Head:       0,
	}
	return c, nil
}
