// RSI codec adapted from loregd; Copyright (c) 2026 The Peios Authors. MIT.
package source

import "testing"

// TestDecodeBeginTransactionMode covers the RSI_BEGIN_TRANSACTION payload
// (PSPK §4.4): a u64 transaction id followed by a u32 mode. Both defined
// modes decode and trailing bytes are tolerated.
func TestDecodeBeginTransactionMode(t *testing.T) {
	cases := []struct {
		name     string
		build    func(*Encoder)
		wantTxn  uint64
		wantMode uint32
	}{
		{
			name:     "read-write explicit",
			build:    func(e *Encoder) { e.PutUint64(7); e.PutUint32(TxnReadWrite) },
			wantTxn:  7,
			wantMode: TxnReadWrite,
		},
		{
			name:     "read-only explicit",
			build:    func(e *Encoder) { e.PutUint64(8); e.PutUint32(TxnReadOnly) },
			wantTxn:  8,
			wantMode: TxnReadOnly,
		},
		{
			name:     "trailing bytes tolerated",
			build:    func(e *Encoder) { e.PutUint64(9); e.PutUint32(TxnReadOnly); e.PutUint32(0xdead) },
			wantTxn:  9,
			wantMode: TxnReadOnly,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := NewEncoder(16)
			tc.build(e)
			r, err := DecodeBeginTransactionRequest(NewDecoder(e.Bytes()))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if r.TxnID != tc.wantTxn {
				t.Errorf("TxnID = %d, want %d", r.TxnID, tc.wantTxn)
			}
			if r.Mode != tc.wantMode {
				t.Errorf("Mode = %d, want %d", r.Mode, tc.wantMode)
			}
		})
	}
}

// TestDecodeBeginTransactionRejectsTruncation checks that a payload missing
// all or part of the mode field fails to decode instead of selecting a
// writable transaction.
func TestDecodeBeginTransactionRejectsTruncation(t *testing.T) {
	e := NewEncoder(12)
	e.PutUint64(10)
	e.PutUint32(TxnReadOnly)
	full := e.Bytes()
	for n := 0; n < len(full); n++ {
		if _, err := DecodeBeginTransactionRequest(NewDecoder(full[:n])); err == nil {
			t.Errorf("payload of %d bytes decoded; want an error", n)
		}
	}
}
