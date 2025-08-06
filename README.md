# TCP
TCP stack that can handle out-of-order packets, retransmissions and reassembly, zero-window probing, three-way handshake, and connection teardown.
Built in collaboration with Roberto Gonzales Matos for CS1680 at Brown :) This is built from scratch on top of our custom IP stack and uses UDP sockets to simulate the link layer. 
`pkg/tcp` contains the bulk of the implementation. Running `make` in the top-level directory builds `vhost` and `vrouter`.
