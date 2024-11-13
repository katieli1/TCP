package tcp

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

func REPL() {
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
			go func() {
				VSend(int16(entry), message)
			}()
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
			fmt.Println("bytesToRead", bytesToRead)
			if err != nil {
				fmt.Printf("Invalid bytes to read: %s\n", words[2])
				continue
			}

			buffer := make([]byte, bytesToRead)
			err = VRead(int16(port), buffer)
			if err != nil {
				// Handle error
			}
			fmt.Printf("Read %d bytes: %s\n", len(buffer), string(buffer))

		} else {
			fmt.Println("Invalid command. Valid commands include li, ln, lr, up <ifname>, down <ifname>, send <addr> <message ...>, and q to quit.")
		}
	}
}

func ACommand(port int16) {
	listenConn := VListen(port)
	listenerTable[port] = listenConn
	fourtupleOrder = append(fourtupleOrder, OrderInfo{port, nil})
	for {
		_, err := listenConn.VAccept()
		if err != nil {
			fmt.Println("Error ", err)
		}

	}
}
