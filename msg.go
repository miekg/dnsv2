package dns

import "fmt"

type (
	MsgHeader struct {
		Question   int
		Answer     int
		Authority  int
		Additional int
	}

	// Msg is a DNS message which is used in the query and the response. It's defined as follows:
	//
	//   +---------------------+
	//   |        Header       |
	//   +---------------------+
	//   |       Question      | the question for the name server
	//   +---------------------+
	//   |        Answer       | RRs answering the question
	//   +---------------------+
	//   |      Authority      | RRs pointing toward an authority
	//   +---------------------+
	//   |      Additional     | RRs holding additional information
	//   +---------------------+
	//
	// Even though the protocol allows multiple questions, in practice only 1 is allowed, this package enforces
	// that convention.
	// After setting any RR, Buf may be written to the wire as it will contain a valid DNS message. Buf
	Msg struct {
		Header MsgHeader
		// An initial buf (before any writes) may be set. Access buf is valid after the first Set on Msg.
		buf         []byte         // buf is the msg buffer as created or recieved from the wire.
		rindex      int            // reader index.
		windex      int            // writer index.
		compression map[string]int // name to index for the compression pointers.
		curSection  Section        // current section we're writing to keep track of where we are.
	}

	Section int
)

const (
	SectionQuestion Section = iota
	SectionAnswer
	SectionAuthority
	SectionAdditional
)

func NewMsg(buf []byte) *Msg {
	m := new(Msg)
	m.buf = buf
	return m
}

// Reset resets the message m, so it can be used again.
func (m *Msg) Reset() {

}

func (m *Msg) Bytes() []byte { return m.buf[:m.windex] }

// SetRR adds RR's wireformat to the msg m in the specified section. As we build the message layer for layer, the ordering
// is important. It needs to be done in the order as specified on the Msg struct.
func (m *Msg) SetRR(section Section, rr RR) error {
	if section < m.curSection {
		return fmt.Errorf("bla")
	}
	if section == SectionQuestion {
		if m.Header.Question == 1 {
			return fmt.Errorf("bla")
		}
		switch rr.(type) {
		case *Question:
			break // ok
		default:
			return fmt.Errorf("bla")
		}
		buf := Bytes(rr)
		copy(m.buf[12+1:], buf)
		m.windex = 12 + len(buf)
		m.Header.Question = 1
		m.curSection = SectionAnswer
		return nil
	}

	buf := Bytes(rr)
	copy(m.buf[m.windex+1:], buf)
	m.windex += len(buf)
	m.curSection = section
	switch section {
	case SectionAnswer:
		m.Header.Answer++
	case SectionAuthority:
		m.Header.Authority++
	case SectionAdditional:
		m.Header.Additional++
	}
	return nil
}

// RR returns the next RR from the specified section. If none are found, nil is returned.
func (m *Msg) RR(section Section) RR {
	return nil
}

// func (m *Msg) Walk()
