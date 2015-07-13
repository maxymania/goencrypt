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

import "io"
import "bytes"

type CipherWriter struct{
	C BufferedCipher
	W io.Writer
	Err error
	Buf []byte
}
func NewCipherWriter(c BufferedCipher, w io.Writer) *CipherWriter {
	return &CipherWriter{c,w,nil,nil}
}
func (c *CipherWriter) Write(src []byte) (n int, err error){
	if c.Err!=nil { return 0,c.Err }
	{
		lng := c.C.UpdateOutputSize(len(src))
		if len(c.Buf)<lng { c.Buf = make([]byte,lng) }
	}
	m,e := c.C.ProcessBytes(c.Buf,src)
	if e!=nil { return 0,e }
	n,err = c.W.Write(c.Buf[:m])
	if n<m {
		if err == nil { // should never happen
			err = io.ErrShortWrite
		}
	}
	n = len(src)-(m-n)
	if n<0 { n=0 }
	return
}

type CipherReader struct{
	C BufferedCipher
	R io.Reader
	Buf []byte
	Buf2 []byte
	h *bytes.Reader
}
func NewCipherReader(c BufferedCipher,r io.Reader) *CipherReader {
	return &CipherReader{c,r,nil,nil,nil}
}
func (c *CipherReader) Read(dst []byte) (n int, err error) {
	if c.Buf==nil {
		c.Buf = make([]byte,1<<13)
		c.Buf2 = make([]byte,len(c.Buf)+c.C.MaxOverhead())
	}
	if c.h!=nil {
		n,err = c.h.Read(dst)
		if c.h.Len()==0 { c.h=nil }
		return
	}
	r,e := c.R.Read(c.Buf)
	if e!=nil { return 0,e }
	m,e := c.C.ProcessBytes(c.Buf2,c.Buf[:r])
	if e!=nil { return 0,e }
	c.h = bytes.NewReader(c.Buf2[:m])
	n,err = c.h.Read(dst)
	if c.h.Len()==0 { c.h=nil }
	return
}


