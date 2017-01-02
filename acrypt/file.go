package acrypt

import (
	"encoding/gob"
	"io"
)

// AftercrypFile struct for serialising.
type File struct {
	Nonce   []byte
	Key     Key
	Payload []byte
}

type Key struct {
	Salt []byte
	N    int
	R    int
	P    int
}

func NewKey(salt []byte) Key {
	return Key{
		Salt: salt,
		N:    Settings.N,
		R:    Settings.R,
		P:    Settings.P,
	}
}

func (af *File) Serialize(w io.Writer) error {

	encoder := gob.NewEncoder(w)
	return encoder.Encode(af)
}

func Deserialize(r io.Reader) (*File, error) {

	f := &File{}
	decoder := gob.NewDecoder(r)
	if err := decoder.Decode(f); err != nil {
		return nil, err
	}
	return f, nil
}
