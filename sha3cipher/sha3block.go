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
	"sync"
	"crypto/cipher"
	"golang.org/x/crypto/sha3"
)

func bxor(dst, src []byte) {
	for i,d := range src {
		dst[i]^=d
	}
}

type block struct{
	m          sync.Mutex
	halfblock  int
	rounds     int
	keyparts   [][]byte
	feistelIn  []byte
	feistelOut []byte
	r,l        []byte
}
func (b *block) BlockSize() int {
	return b.halfblock*2
}
func (b *block) Encrypt(dst, src []byte) {
	b.m.Lock(); defer b.m.Unlock()
	copy(b.r,src[:b.halfblock])
	copy(b.l,src[b.halfblock:])
	for i:=0 ; i<b.rounds; i+=2 {
		copy(b.feistelIn,b.r)
		copy(b.feistelIn[b.halfblock:],b.keyparts[i+0])
		sha3.ShakeSum256(b.feistelOut,b.feistelIn)
		bxor(b.l,b.feistelOut)
		//--------------------------------------------
		copy(b.feistelIn,b.l)
		copy(b.feistelIn[b.halfblock:],b.keyparts[i+1])
		sha3.ShakeSum256(b.feistelOut,b.feistelIn)
		bxor(b.r,b.feistelOut)
	}
	copy(dst[:b.halfblock],b.r)
	copy(dst[b.halfblock:],b.l)
}

func (b *block) Decrypt(dst, src []byte) {
	b.m.Lock(); defer b.m.Unlock()
	copy(b.r,src[:b.halfblock])
	copy(b.l,src[b.halfblock:])
	for i:=b.rounds-2 ; i>=0; i-=2 {
		copy(b.feistelIn,b.l)
		copy(b.feistelIn[b.halfblock:],b.keyparts[i+1])
		sha3.ShakeSum256(b.feistelOut,b.feistelIn)
		bxor(b.r,b.feistelOut)
		//--------------------------------------------
		copy(b.feistelIn,b.r)
		copy(b.feistelIn[b.halfblock:],b.keyparts[i+0])
		sha3.ShakeSum256(b.feistelOut,b.feistelIn)
		bxor(b.l,b.feistelOut)
	}
	copy(dst[:b.halfblock],b.r)
	copy(dst[b.halfblock:],b.l)
}

/*
  Initialized a new Block cipher. The block size (bzize) and the number of rounds must be a multiple of 2.
  The number of bytes within the key must be a multiple of rounds.
 */
func NewBlock(bsize, rounds int,key []byte) (cipher.Block,error) {
	if (bsize&1) == 1 { return nil,ErrOddBlockSize }
	if (rounds&1) == 1 { return nil,ErrOddRoundsNum }
	if (len(key)%rounds) !=0 { return nil,ErrKeySizeRounds }
	kpart := len(key)/rounds
	b := new(block)
	b.halfblock = bsize/2
	b.rounds = rounds
	b.keyparts = make([][]byte,rounds)
	for i := 0 ; i<rounds ; i++ {
		b.keyparts[i] = key[kpart*i:kpart*(i+1)]
	}
	b.feistelIn  = make([]byte,b.halfblock+kpart)
	b.feistelOut = make([]byte,b.halfblock)
	b.r          = make([]byte,b.halfblock)
	b.l          = make([]byte,b.halfblock)
	return b,nil
}


