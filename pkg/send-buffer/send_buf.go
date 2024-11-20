package pkgUtils

import (
	"fmt"
	buf "ip/pkg/buffer"
	"sync"
)

type SendBuf struct {
	UNA         int16
	Buf         buf.Buffer
	Chan        chan int16
	StartingSeq int
	Queue       []Packet // holds all unACKed packets
	QueueMutex  sync.RWMutex
}

type Packet struct {
	Seq  int16
	Data []byte
}

type RecieveBuf struct {
	Buf  buf.Buffer
	Chan chan int16
}

func (b *SendBuf) Write(data []byte) {
	b.Buf.Write(data)
	b.Queue = append(b.Queue, Packet{Seq: 0, Data: data})
}

func (b *SendBuf) Read(numBytes int16) (data []byte) {
	return b.Buf.Read(numBytes)
}

func (b *SendBuf) UpdateUNA(newPos int16) {
	b.UNA = (newPos - int16(b.StartingSeq) - 1) % b.Buf.Len
	// if newPos >= b.Buf.Len {
	// 	newPos = newPos - b.Buf.Len
	// }
	// b.UNA = newPos
	// fmt.Println("updating UNA: ", b.UNA)
}

func (b *SendBuf) GetDataToSend(length int16) (data []byte) {

	// fmt.Println("head ", b.Buf.Head)
pointer := (b.Buf.Head - length + b.Buf.Len) % b.Buf.Len	
	fmt.Println("pointer ", pointer)
	if pointer < b.Buf.Head {
		// fmt.Println("no wraparound")
		return b.Buf.Arr[pointer:b.Buf.Head]
	} else {
		// fmt.Println("wraparound")
		firstChunk := b.Buf.Arr[pointer:b.Buf.Len]
		secondChunk := b.Buf.Arr[0:b.Buf.Head]
		return append(firstChunk, secondChunk...)
	}

}

func (b *SendBuf) GetWindowSize() (windowSize int16) {
	return b.Buf.WindowSize
}
