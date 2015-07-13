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

type wrappedStream struct{
	inner cipher.Stream
}
func (w wrappedStream) MaxOverhead() int { return 0 }
func (w wrappedStream) UpdateOutputSize(srcLength int) int { return srcLength }
func (w wrappedStream) ProcessBytes(dst []byte, src []byte) (int,error) {
	w.inner.XORKeyStream(dst,src)
	return len(src),nil
}

// creates a BufferedCipher wrapper for a cipher.Stream object.
// This is especially useful for use in conjunction with CipherWriter, as
// CipherWriter is more efficient than cipher.StreamWriter.
func BufferedStreamCipher(s cipher.Stream) BufferedCipher {
	return wrappedStream{s}
}

