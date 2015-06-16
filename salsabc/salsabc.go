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

/*
 This package is the reference implementation of the SalsaBC block cipher.
 SalsaBC is a balanced 4 round feistel cipher using Salsa20/8 core as its
 Feistel function. It has an 1024 bit block size and an 2048 bit key size.
*/
package salsabc

import "golang.org/x/crypto/salsa20/salsa"
import "crypto/cipher"
import "errors"

var ErrWrongKeySize = errors.New("goencrypt/salsabc: Keysize != 256")

func bcp(dst, src *[64]byte) {
	for i:=0 ; i<64; i++ {
		(*dst)[i]=src[i]
	}
}

func bxor(dst, src *[64]byte) {
	for i:=0 ; i<64; i++ {
		(*dst)[i]^=src[i]
	}
}


type block struct{
	key [4][64]byte
}
func (b *block) BlockSize() int {
	return 128
}
func (b *block) Encrypt(dst, src []byte) {
	var r,l,i,o [64]byte
	copy(r[:],src[:64])
	copy(l[:],src[64:])
	bcp(&i,&r); bxor(&i,&(b.key[0])); salsa.Core208(&o,&i); bxor(&l,&o)
	bcp(&i,&l); bxor(&i,&(b.key[1])); salsa.Core208(&o,&i); bxor(&r,&o)
	bcp(&i,&r); bxor(&i,&(b.key[2])); salsa.Core208(&o,&i); bxor(&l,&o)
	bcp(&i,&l); bxor(&i,&(b.key[3])); salsa.Core208(&o,&i); bxor(&r,&o)
	copy(dst[:64],r[:])
	copy(dst[64:],l[:])
}
func (b *block) Decrypt(dst, src []byte) {
	var r,l,i,o [64]byte
	copy(r[:],src[:64])
	copy(l[:],src[64:])
	bcp(&i,&l); bxor(&i,&(b.key[3])); salsa.Core208(&o,&i); bxor(&r,&o)
	bcp(&i,&r); bxor(&i,&(b.key[2])); salsa.Core208(&o,&i); bxor(&l,&o)
	bcp(&i,&l); bxor(&i,&(b.key[1])); salsa.Core208(&o,&i); bxor(&r,&o)
	bcp(&i,&r); bxor(&i,&(b.key[0])); salsa.Core208(&o,&i); bxor(&l,&o)
	copy(dst[:64],r[:])
	copy(dst[64:],l[:])
}

/*
 Returns a new block cipher withe the block size of 128 bytes (1024 bit).
 The key must be 256 bytes long (2048 bit).
 */
func NewBlock(key []byte) (cipher.Block,error) {
	if len(key)!=256 { return nil,ErrWrongKeySize }
	b := new(block)
	copy(b.key[0][:],key[:64])
	copy(b.key[1][:],key[64:128])
	copy(b.key[2][:],key[128:192])
	copy(b.key[3][:],key[192:])
	return b,nil
}



