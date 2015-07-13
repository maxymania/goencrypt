/*
   Copyright 2015 Simon Schmidt

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package cipher2

import "crypto/cipher"

type bufferedBlockCipher struct{
	mode   cipher.BlockMode
	blkSiz int
	buf    []byte
	bufOff int
}
func newbufferedBlockCipher(mode cipher.BlockMode) *bufferedBlockCipher {
	return &bufferedBlockCipher{
		mode:mode,
		blkSiz:mode.BlockSize(),
		buf:make([]byte,mode.BlockSize()),
		bufOff:0,
	}
}
func (b *bufferedBlockCipher) MaxOverhead() int {
	return b.blkSiz-1
}

func (b *bufferedBlockCipher) UpdateOutputSize(srcLength int) int {
	n := b.bufOff+srcLength
	n -= n%b.blkSiz
	return n
}

func (b *bufferedBlockCipher) ProcessBytes(dst []byte, src []byte) (n int,err error) {
	n = 0
	err = nil
	if b.bufOff!=0 {
		rest := b.blkSiz-b.bufOff
		copy(b.buf[b.bufOff:],src[:rest])
		b.bufOff+=rest
		if b.bufOff<b.blkSiz { return }
		b.mode.CryptBlocks(dst[:b.blkSiz],b.buf)
		n += b.blkSiz
		dst=dst[b.blkSiz:]
		src=src[rest:]
	}
	il := len(src)
	il -= il%b.blkSiz
	b.mode.CryptBlocks(dst[:il],src[:il])
	n += il
	dst = dst[il:]
	src = src[il:]
	b.bufOff=len(src)
	copy(b.buf[:b.bufOff],src)
	return
}

// Creates a new Buffered version of the given block cipher in an block cipher mode
func NewBufferedBlockCipher(mode cipher.BlockMode) BufferedCipher {
	return newbufferedBlockCipher(mode)
}


