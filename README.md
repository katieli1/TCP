# IP README

## How you build your abstractions for the IP layer and interfaces (What data structures do you have? How do your vhost and vrouter programs interact with your shared IP stack code?)
Our shared IP stack code handles the vast majority of program logic. It maintains the lookup and forwarding tables, the command-line interface, logic for sending packets, logic for reading from the interface(s) to receive and process packets, and (in the case of routers) tracks timeouts for nodes that it hasn't heard RIP updates about.

The vhost and vrouter programs interact with the shared IP stack code by registering callback function(s) for certain protocols; both register a callback function (using the RegisterRecvHandler function) that simply prints the received message (for test packets, or packets with protocolNum = 0). The vrouter also registers an additional callback function that handles processing RIP updates (packets with protocolNum = 200); this function updates the lookup/forwarding tables in accordance with the contents of the RIP update. 

## How you use threads/goroutines
Our shared IP stack maintains a goroutine for each of its interfaces that continuously reads from the UDP connection and processes the packet using the SendIP function (SendIP will check whether it's one of the current node's packets and call the callback function if it is; else it will forward the packet to the next node). It also uses a goroutine to manage the REPL.

For routers only:
The shared stack also maintains a goroutine (only if a router is using it) that continuously iterates through all known subnets and makes sure it has received updates before the timeout limit. 
It also maintains a goroutine per interface that continuously sends RIP updates to other routers about all the nodes it knows about. 

## The steps you will need to process IP packets
We process IP packets in the following manner:
- In an interface's corresponding readConn goroutine, it will read from the UDP connection if/when it receives data. It will then call SendIP, which does the remainder of these steps.
- If checksum or TTL are invalid, drop the packet
- If it's one of "my" packets, call the callback function that corresponds to the protocolNum (this will print the packet if it's a test packet, else performs a RIP update)
- Identify the best-match prefix in our lookup table (that matches the final destination)
- Based on the result, forward to next hop interface or use next hop address to perform a second lookup that identifies the next hop interface

