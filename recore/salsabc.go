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
 This package is the implements ReCore a experimental block cipher derived
 from SalsaBC.
 It is a balanced 4 round feistel cipher using Salsa20/8 core as its
 Feistel function. It has an 1024 bit block size and an 2048 bit key size.
 ReCore fixes potential security flaws of SalsaBC
*/
package recore

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
	bcp(&i,&r); salsa.Core208(&o,&i); bxor(&o,&(b.key[0])); salsa.Core208(&i,&o); bxor(&l,&i)
	bcp(&i,&l); salsa.Core208(&o,&i); bxor(&o,&(b.key[1])); salsa.Core208(&i,&o); bxor(&r,&i)
	bcp(&i,&r); salsa.Core208(&o,&i); bxor(&o,&(b.key[2])); salsa.Core208(&i,&o); bxor(&l,&i)
	bcp(&i,&l); salsa.Core208(&o,&i); bxor(&o,&(b.key[3])); salsa.Core208(&i,&o); bxor(&r,&i)
	copy(dst[:64],r[:])
	copy(dst[64:],l[:])
}
func (b *block) Decrypt(dst, src []byte) {
	var r,l,i,o [64]byte
	copy(r[:],src[:64])
	copy(l[:],src[64:])
	bcp(&i,&l); salsa.Core208(&o,&i); bxor(&o,&(b.key[3])); salsa.Core208(&i,&o); bxor(&r,&i)
	bcp(&i,&r); salsa.Core208(&o,&i); bxor(&o,&(b.key[2])); salsa.Core208(&i,&o); bxor(&l,&i)
	bcp(&i,&l); salsa.Core208(&o,&i); bxor(&o,&(b.key[1])); salsa.Core208(&i,&o); bxor(&r,&i)
	bcp(&i,&r); salsa.Core208(&o,&i); bxor(&o,&(b.key[0])); salsa.Core208(&i,&o); bxor(&l,&i)
	copy(dst[:64],r[:])
	copy(dst[64:],l[:])
}

/*
 Returns a new block cipher withe the block size of 128 bytes (1024 bit).
 The key must be 256 bytes long (2048 bit).
 */
func NewBlock(key []byte) (cipher.Block,error) {
	var buf [64]byte
	if len(key)!=256 { return nil,ErrWrongKeySize }
	b := new(block)
	copy(buf[:],key[:64]);     salsa.Core208(&(b.key[0]),&buf)
	copy(buf[:],key[64:128]);  salsa.Core208(&(b.key[1]),&buf)
	copy(buf[:],key[128:192]); salsa.Core208(&(b.key[2]),&buf)
	copy(buf[:],key[192:]);    salsa.Core208(&(b.key[3]),&buf)
	return b,nil
}



