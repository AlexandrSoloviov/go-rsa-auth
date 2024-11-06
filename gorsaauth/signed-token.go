package gorsaauth

import (
	"encoding/binary"
	"time"
)

func (st SignedToken) Id() string {
	id_bytes := st.data[0:8]
	return string(id_bytes)
}

func (st SignedToken) ExpiredAt() time.Time {
	token_length := len(st.data)
	et_bytes := st.data[token_length-8 : token_length]
	ts := binary.LittleEndian.Uint64(et_bytes)
	t := time.Unix(0, int64(ts))
	return t
}
