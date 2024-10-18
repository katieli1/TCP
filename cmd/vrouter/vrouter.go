package main

import (
	"fmt"
	"ip/pkg/lookup"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

func callback_test(msg string, nextHop netip.Addr, networkTable map[netip.Prefix]*lookup.NetworkEntry, maxCost int) {
	fmt.Println("Received test packet: " + msg)
}
func callback_rip(message string, nextHop netip.Addr, networkTable map[netip.Prefix]*lookup.NetworkEntry, maxCost int) {
	// fmt.Println("In Callback, message:", message)
	var routes []lookup.RouteInfo
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

		addr, err := netip.ParseAddr(strings.TrimSpace(strings.ReplaceAll(fields[2], "\x00", "")))
		if err != nil {
			fmt.Println("Invalid address:", fields[2], "Error:", err)
			continue
		}
		//if it is one of my interfaces, don't add it
		routes = append(routes, lookup.RouteInfo{
			Cost:         cost,
			PrefixLength: prefixLength,
			Address:      addr,
		})
		// fmt.Println("Parsed route: address =", addr.String(), ", cost =", cost, ", prefix length =", prefixLength)
	}

	for _, route := range routes {
		prefix := netip.PrefixFrom(route.Address, route.PrefixLength)
		// fmt.Println("Processing route for prefix:", prefix.String())

		networkAddr := prefix.Masked().Addr()
		maskedPrefix := netip.PrefixFrom(networkAddr, prefix.Bits())
		if entry, exists := networkTable[maskedPrefix]; exists {
			if entry.Name != "" {
				continue
			}
			if neighbor, found := entry.LookupTable[route.Address]; found {
				//poison reverse - split horizon
				newCost := route.Cost + 1
				if newCost >= maxCost {
					// Mark route as unreachable by setting maxCost
					neighbor.Cost = maxCost
				} else if neighbor.NextHop == nextHop || neighbor.Cost > newCost {
					neighbor.Cost = newCost
					neighbor.NextHop = nextHop
					entry.LookupTable[route.Address].LastHeard = time.Now()
				}
			} else {
				fmt.Println("Adding new neighbor:", route.Address.String())

				entry.LookupTable[route.Address] = &lookup.Neighbor{
					DestAddr: route.Address,
					Cost:     route.Cost + 1,
					IpPrefix: maskedPrefix,
					NextHop:  nextHop,
					WillHop:  true,
				}
			}

		} else {
			newEntry := &lookup.NetworkEntry{
				IpPrefix:    maskedPrefix,
				IpAddr:      nextHop,
				LookupTable: make(map[netip.Addr]*lookup.Neighbor),
				Up:          true,
				IsDefault:   false,
			}
			newEntry.LookupTable[route.Address] = &lookup.Neighbor{
				DestAddr:  route.Address,
				Cost:      route.Cost + 1,
				IpPrefix:  maskedPrefix,
				NextHop:   nextHop,
				WillHop:   true,
				LastHeard: time.Now(),
			}
			networkTable[maskedPrefix] = newEntry
		}

	}

}

func main() {
	// if len(os.Args) != 3 {
	// 	fmt.Printf("Usage:  %s --config <configFile>\n", os.Args[0])
	// 	os.Exit(1)
	// }
	fileName := os.Args[2]
	lookup.RegisterRecvHandler(0, callback_test)
	lookup.RegisterRecvHandler(200, callback_rip)
	lookup.Initialize(fileName)

}
