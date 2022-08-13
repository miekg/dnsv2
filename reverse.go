package dns

// Reverse maps.

func reverseOpcode(m map[Opcode]string) map[string]Opcode {
	n := make(map[string]Opcode, len(m))
	for u, s := range m {
		n[s] = u
	}
	return n
}

func reverseClass(m map[Class]string) map[string]Class {
	n := make(map[string]Class, len(m))
	for u, s := range m {
		n[s] = u
	}
	return n
}

func reverseRcode(m map[Rcode]string) map[string]Rcode {
	n := make(map[string]Rcode, len(m))
	for u, s := range m {
		n[s] = u
	}
	return n
}

func reverseType(m map[Type]string) map[string]Type {
	n := make(map[string]Type, len(m))
	for u, s := range m {
		n[s] = u
	}
	return n
}

/*
func reverseInt16(m map[uint16]string) map[string]uint16 {
	n := make(map[string]uint16, len(m))
	for u, s := range m {
		n[s] = u
	}
	return n
}

func reverseInt(m map[int]string) map[string]int {
	n := make(map[string]int, len(m))
	for u, s := range m {
		n[s] = u
	}
	return n
}
*/
