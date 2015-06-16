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
 This package implements encryption algorithms based on sha3 SHAKE.
*/
package sha3cipher

import "errors"

var ErrOddBlockSize = errors.New("goencrypt/sha3cipher: Block size not a multiple of 2")
var ErrOddRoundsNum = errors.New("goencrypt/sha3cipher: Rounds number not a multiple of 2")
var ErrKeySizeRounds = errors.New("goencrypt/sha3cipher: Number of key bytes not a multiple of rounds")

var ErrIvZero = errors.New("goencrypt/sha3cipher: IV-Length is 0")
var ErrKeyZero = errors.New("goencrypt/sha3cipher: Key-Length is 0")

