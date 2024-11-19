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
			orderStruct := fourtupleOrder[entry]

			if orderStruct.VConn == nil {
				// Cannot send message to a listener entry
				return
			}
			go func() {
				orderStruct.VConn.VWrite(message)
			}()
		} else if words[0] == "cl" { // close
			if len(words) < 2 {
				fmt.Println("Usage: cl <port>")
				continue
			}
			entry, err := strconv.ParseInt(words[1], 10, 16)
			if err != nil {
				fmt.Printf("Invalid entry: %s\n", words[1])
				continue
			}

			orderStruct := fourtupleOrder[entry]

			if orderStruct.VConn == nil {
				// this is a listener entry
				go func() {
					listener, exists := listenerTable[orderStruct.Port]
					if exists {

						listener.VClose()
					}
				}()
			} else {
				go func() {
					orderStruct.VConn.VClose()
				}()
			}

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

			file := words[1]

			ip, err := netip.ParseAddr(words[2])
			if err != nil {
				fmt.Println("Error:", err)

			}
			port, err := strconv.ParseInt(words[3], 10, 16)
			if err != nil {
				fmt.Println("Error:", err)

			}

			go SendFiles(ip, int16(port), file)

		} else if words[0] == "rf" {

			file := words[1]
			port, err := strconv.ParseInt(words[2], 10, 16)
			if err != nil {
				fmt.Println("Error:", err)

			}

			go ReceiveFiles(int16(port), file)

		} else if words[0] == "r" { // receive data on a socket
			if len(words) < 3 {
				fmt.Println("Usage: r <ID> <bytes_to_read>")
				continue
			}

			ID, err := strconv.ParseInt(words[1], 10, 16)
			if err != nil {
				fmt.Printf("Invalid ID number: %s\n", words[1])
				continue
			}

			bytesToRead, err := strconv.ParseInt(words[2], 10, 16)
			fmt.Println("bytesToRead", bytesToRead)
			if err != nil {
				fmt.Printf("Invalid bytes to read: %s\n", words[2])
				continue
			}

			buffer := make([]byte, bytesToRead)
			orderStruct := fourtupleOrder[int16(ID)]

			if orderStruct.VConn == nil {
				// Cannot send message to a listener entry
				return
			}
			bytesRead, err := orderStruct.VConn.VRead(buffer)
			if err != nil {
				// Handle error
			}
			fmt.Printf("Read %d bytes: %s\n", bytesRead, string(buffer))

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
