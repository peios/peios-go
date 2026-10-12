package security

import "testing"

func TestDecimalRights(t *testing.T) {
	for text, want := range map[string]uint32{"0": 0, "000": 0, "1179817": 0x1200a9, "001179817": 0x1200a9, "4294967295": 0xffffffff, "0x6": 6, "FRFX0x6": 0x1200af} {
		got, err := words(rights_parse, text, true)
		if err != nil || got != want {
			t.Errorf("%q: %x %v, want %x", text, got, err, want)
		}
	}
	for _, text := range []string{"4294967296", "-1", "+1", "١", "1179817FR", "FR1179817"} {
		if _, err := words(rights_parse, text, true); err == nil {
			t.Errorf("accepted %q", text)
		}
	}
	d, err := ParseSDDL("D:(A;;1179817;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	if d.DACL.ACEs[0].Mask != 0x1200a9 {
		t.Fatal("decimal mask changed")
	}
	if _, err := d.MarshalBinary(); err != nil {
		t.Fatal(err)
	}
}
