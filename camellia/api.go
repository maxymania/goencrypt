/* Copyright 2015 Simon Schmidt */

/*
 Package camellia is an implementation of the CAMELLIA encryption algorithm,
 based on a Go port of the OpenSSL C code.
 Like the OpenSSL code, it available under a permissive non-GPL-License.
 
 IMPORTANT: This library is not subject to the Apache license.

 ALSO IMPORTANT: The translation basically works, but it is not guaranteed, that it doesnt violate the Spec.
 */
package camellia

import "errors"

var WrongKeySizeError = errors.New("goencrypt/camellia: the keysize is != 16,24 or 32 bytes")

// This structure eases the usage of this cipher.
// It implements the cipher.Block interface
type Camellia struct{
	rounds int
	table *KEY_TABLE_TYPE
}
// Initializes the structure. Must be called before any Encrypt or Decrypt method.
// Key length should be one of 16,24 or 32.
func (c *Camellia) Init(key []byte) error{
	switch len(key){
	case 16,24,32:
		c.table = new(KEY_TABLE_TYPE)
		c.rounds = Camellia_Ekeygen(len(key)*8,key,c.table)
	default:
		return WrongKeySizeError
	}
	return nil
}
func (c *Camellia) Encrypt(dest, src []byte) {
	Camellia_EncryptBlock_Rounds(c.rounds,src,c.table,dest)
}
func (c *Camellia) Decrypt(dest, src []byte) {
	Camellia_DecryptBlock_Rounds(c.rounds,src,c.table,dest)
}
func (c *Camellia) BlockSize() int {
	return 16
}
