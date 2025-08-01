// Package dnswire deals with the encoding from and to wire encoding. In Go these functions are usually called
// Marshal and Unmarshall.
package dnswire

type (
	Type  uint16 // Type is an RR type.
	TTL   int32  // TTL is the time to live of an RR(set).
	Class uint16 // Class is a DNS class.
	Name  []byte // Name is a domain name.
)
