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
 Implements the cipher.Stream version of salsa20 ontop of "golang.org/x/crypto/salsa20".
*/
package salsa20s

import "golang.org/x/crypto/salsa20/salsa"
import "errors"
import "crypto/cipher"
import "fmt"

var null64 = make([]byte,64)

func init(){
	for i:=range null64{null64[i]=0}
}

// Increments a Salsa20 counter
func Ctri(ctr *[16]byte){
	u := uint(1)
	for i := 8; i<16; i++ {
		u += uint(ctr[i])
		ctr[i] = byte(u)
		u>>=8
	}
}

func KeyShedule(nonce []byte, key *[32]byte) (*[16]byte,*[32]byte){
	if len(nonce)==8 {
		r := new([16]byte)
		copy(r[:],nonce)
		return r,key
	}
	if len(nonce)==24 {
		r := new([16]byte)
		k := new([32]byte)
		copy(r[:],nonce[:16])
		salsa.HSalsa20(k, r, key, &salsa.Sigma)
		r = new([16]byte)
		copy(r[:],nonce[16:])
		return r,k
	}
	panic("salsa20s: nonce must be 8 or 24 bytes")
}

func MakeSalsaCipher(nonce []byte, key *[32]byte) (ciph cipher.Stream,err error) {
	defer func(){
		r := recover()
		if r!=nil { err = errors.New(fmt.Sprint(r)); ciph=nil }
	}()
	i,k := KeyShedule(nonce,key)
	ciph = &SalsaCipher{i,k,make([]byte,64),0}
	return
}

type SalsaCipher struct {
	Counter *[16]byte
	Key *[32]byte
	Buffer []byte //64 bytes
	Pos int
}
func (s *SalsaCipher) XORKeyStream(dst, src []byte) {
	for i,b := range src{
		if s.Pos==0 {
			salsa.XORKeyStream(s.Buffer,null64,s.Counter,s.Key)
			Ctri(s.Counter)
		}
		dst[i] = b ^ s.Buffer[s.Pos]
		s.Pos = (s.Pos+1)&63
	}
}


