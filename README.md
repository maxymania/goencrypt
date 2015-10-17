# goencrypt
Experimental/new encryption algorithms for Go

Aside this, this library will contain implementations of existing encryption Algorithms.

# Packages

- [sha3cipher](http://godoc.org/github.com/maxymania/goencrypt/sha3cipher) This package implements encryption algorithms based on sha3 SHAKE.
- [recore](http://godoc.org/github.com/maxymania/goencrypt/recore) This package is the implements ReCore a experimental block cipher based on Salsa20.
- [camellia](http://godoc.org/github.com/maxymania/goencrypt/camellia) This package is a port of OpenSSLs CAMELLIA implementation, not Apache Licensed, but non-GPL
- [cipher2](http://godoc.org/github.com/maxymania/goencrypt/cipher2) This package provides an extension for crypto/cipher, namely streaming for Block-Cipher encoded data.
- [salsa20s](http://godoc.org/github.com/maxymania/goencrypt/salsa20s) Implements the cipher.Stream version of salsa20 ontop of "golang.org/x/crypto/salsa20".

# License (Apache license)

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

NOTE: There may be algorithms, parts or dependencies, distributed under different license.
