all: 
	go build ./cmd/vhost
	go build ./cmd/vrouter
	go build ./test/test_buffer

clean:
	rm -fv vhost vrouter test_buffer