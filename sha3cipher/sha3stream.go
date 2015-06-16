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

package sha3cipher

import (
	"crypto/cipher"
	"golang.org/x/crypto/sha3"
)

type stream struct{
	blocklen  int
	transfIn  []byte
	transfOut []byte
	pos       int
	decode    bool
}
func (b *stream) encrypt(dst, src []byte) {
	ls := len(src)
	for i:=0 ; i<ls; i++ {
		if b.pos==b.blocklen {
			sha3.ShakeSum256(b.transfOut,b.transfIn)
			b.pos = 0
		}
		b.transfIn[b.pos] ^= src[i]
		dst[i] = b.transfIn[b.pos]
		b.pos++
	}
}
func (b *stream) decrypt(dst, src []byte) {
	ls := len(src)
	for i:=0 ; i<ls; i++ {
		if b.pos==b.blocklen {
			sha3.ShakeSum256(b.transfOut,b.transfIn)
			b.pos = 0
		}
		bak := src[i]
		dst[i] = b.transfIn[b.pos] ^ src[i]
		b.transfIn[b.pos] = bak
		b.pos++
	}
}
func (b *stream) XORKeyStream(dst, src []byte) {
	if b.decode {
		b.decrypt(dst,src)
	} else {
		b.encrypt(dst,src)
	}
}

func makeStream(key, iv []byte) (b *stream,e error) {
	b = new(stream)
	if len(key)==0 { e = ErrKeyZero; return }
	if len(iv)==0 { e = ErrIvZero; return }
	b.blocklen = len(iv)
	b.transfOut = make([]byte,b.blocklen)
	b.transfIn = make([]byte,b.blocklen+len(key))
	copy(b.transfIn[:b.blocklen],iv)
	copy(b.transfIn[b.blocklen:],key)
	sha3.ShakeSum256(b.transfOut,b.transfIn)
	return
}

func NewStreamEncrypter(key, iv []byte) (cipher.Stream,error) {
	c,e := makeStream(key,iv)
	if e!=nil { return nil,e }
	return c,nil
}

func NewStreamDecrypter(key, iv []byte) (cipher.Stream,error) {
	c,e := makeStream(key,iv)
	if e!=nil { return nil,e }
	c.decode = true
	return c,nil
}

