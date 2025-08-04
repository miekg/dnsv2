package dnswire

// typeToString is a map of strings for each RR type.
// copied here to make String() work for type, but leave the definition of TypeToString in
// the main dns package.
var typeToString = map[uint16]string{
	1:  "A",
	15: "MX",
	41: "OPT",
}
