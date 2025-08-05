package dns

func (rr *MX) String() string {
	hdr := rr.Header.String(rr)
}
