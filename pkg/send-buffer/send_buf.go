package pkgUtils

import (
	"fmt"
	buf "ip/pkg/buffer"
)

type SendBuf struct {
	UNA         int16
	Buf         buf.Buffer
	Chan        chan int16
	StartingSeq int
}

func (b *SendBuf) Write(data []byte) {
	b.Buf.Write(data)
}

func (b *SendBuf) Read(numBytes int16) (data []byte) {
	return b.Buf.Read(numBytes)
}

func (b *SendBuf) UpdateUNA(newPos int16) {
	b.UNA = (newPos - int16(b.StartingSeq)) % b.Buf.Len
	// if newPos >= b.Buf.Len {
	// 	newPos = newPos - b.Buf.Len
	// }
	// b.UNA = newPos
	fmt.Println("updating UNA: ", b.UNA)
}

func (b *SendBuf) GetWindowSize() (windowSize int16) {
	return b.Buf.WindowSize
}
