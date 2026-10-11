package msgpack

// Writer incrementally constructs a single MessagePack value. The zero value
// is ready to use. Errors latch until Reset; Bytes checks complete structure
// at libpeios's 256-level codec limit (event emission normally allows 32).
// It is not safe for concurrent mutation.
type Writer struct {
	data []byte
	err  error
}

func (w *Writer) Reset()     { w.data = w.data[:0]; w.err = nil }
func (w *Writer) Err() error { return w.err }
func (w *Writer) value(v any) *Writer {
	if w.err == nil {
		w.data, w.err = appendValue(w.data, v, 1)
	}
	return w
}
func (w *Writer) Nil() *Writer                  { return w.value(nil) }
func (w *Writer) Bool(v bool) *Writer           { return w.value(v) }
func (w *Writer) Int(v int64) *Writer           { return w.value(v) }
func (w *Writer) Uint(v uint64) *Writer         { return w.value(v) }
func (w *Writer) Float(v float64) *Writer       { return w.value(v) }
func (w *Writer) String(v string) *Writer       { return w.value(v) }
func (w *Writer) Binary(v []byte) *Writer       { return w.value(v) }
func (w *Writer) Extension(v Extension) *Writer { return w.value(v) }
func (w *Writer) Array(count uint32) *Writer {
	if w.err == nil {
		w.data, w.err = appendSize(w.data, int(count), 0x90, 16, 0, 0xdc, 0xdd)
	}
	return w
}
func (w *Writer) Map(count uint32) *Writer {
	if w.err == nil {
		w.data, w.err = appendSize(w.data, int(count), 0x80, 16, 0, 0xde, 0xdf)
	}
	return w
}

// Raw appends wire fragments verbatim. The complete result is checked by Bytes.
func (w *Writer) Raw(b []byte) *Writer {
	if w.err == nil {
		w.data = append(w.data, b...)
	}
	return w
}

// Bytes returns a borrowed view, valid until the next mutation. A malformed
// result latches an error; Reset is required before reusing the writer.
func (w *Writer) Bytes() ([]byte, error) {
	if w.err == nil {
		w.err = Validate(w.data, 256)
	}
	if w.err != nil {
		return nil, w.err
	}
	return w.data, nil
}
