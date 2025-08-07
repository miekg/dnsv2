package ddd

func IsDigit(b byte) bool { return b >= '0' && b <= '9' }

func Is[T ~[]byte | ~string](s T) bool {
	return len(s) >= 3 && IsDigit(s[0]) && IsDigit(s[1]) && IsDigit(s[2])
}

func ToByte[T ~[]byte | ~string](s T) byte {
	_ = s[2] // bounds check hint to compiler; see golang.org/issue/14808
	return byte((s[0]-'0')*100 + (s[1]-'0')*10 + (s[2] - '0'))
}
