package security

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

type expression struct {
	height   int
	tag      byte
	text     string
	data     []byte
	children []*expression
}

var comparisons = []wordValue{{"==", 0x80}, {"!=", 0x81}, {"<=", 0x83}, {">=", 0x85}, {"<", 0x82}, {">", 0x84}, {"Contains", 0x86}, {"Any_of", 0x88}, {"Not_Contains", 0x8e}, {"Not_Any_of", 0x8f}}
var unaryOps = []wordValue{{"Not_Device_Member_of_Any", 0x93}, {"Not_Member_of_Any", 0x92}, {"Not_Device_Member_of", 0x91}, {"Not_Member_of", 0x90}, {"Device_Member_of_Any", 0x8c}, {"Member_of_Any", 0x8b}, {"Device_Member_of", 0x8a}, {"Member_of", 0x89}, {"Not_Exists", 0x8d}, {"Exists", 0x87}}

type conditionParser struct {
	s     string
	depth int
}

func ident(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == ':' || c == '.'
}
func (p *conditionParser) space() { p.s = strings.TrimLeft(p.s, " \t\r\n") }
func (p *conditionParser) eat(s string) bool {
	p.space()
	if strings.HasPrefix(p.s, s) {
		p.s = p.s[len(s):]
		return true
	}
	return false
}
func (p *conditionParser) keyword(s string) bool {
	p.space()
	if len(p.s) < len(s) || !strings.EqualFold(p.s[:len(s)], s) || len(p.s) > len(s) && ident(p.s[len(s)]) {
		return false
	}
	p.s = p.s[len(s):]
	return true
}
func (p *conditionParser) expr(min int) (*expression, error) {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > 128 {
		return nil, invalid("condition nesting")
	}
	p.space()
	var left *expression
	var e error
	if p.eat("!") {
		v, err := p.expr(3)
		if err != nil {
			return nil, err
		}
		left = &expression{tag: 0xa2, children: []*expression{v}}
	} else if p.eat("(") {
		left, e = p.expr(0)
		if e != nil {
			return nil, e
		}
		if !p.eat(")") {
			return nil, invalid("condition parenthesis")
		}
	} else {
		for _, op := range unaryOps {
			if p.keyword(op.word) {
				v, err := p.operand()
				if err != nil {
					return nil, err
				}
				left = &expression{tag: byte(op.value), children: []*expression{v}}
				break
			}
		}
		if left == nil {
			v, err := p.operand()
			if err != nil {
				return nil, err
			}
			var op byte
			for _, o := range comparisons {
				if (o.word[0] < 'A' && p.eat(o.word)) || (o.word[0] >= 'A' && p.keyword(o.word)) {
					op = byte(o.value)
					break
				}
			}
			if op == 0 {
				return nil, invalid("expected comparison")
			}
			r, err := p.operand()
			if err != nil {
				return nil, err
			}
			left = &expression{tag: op, children: []*expression{v, r}}
		}
	}
	for {
		p.space()
		prec := 0
		var tag byte
		if strings.HasPrefix(p.s, "||") {
			prec = 1
			tag = 0xa1
		} else if strings.HasPrefix(p.s, "&&") {
			prec = 2
			tag = 0xa0
		}
		if prec == 0 || prec < min {
			break
		}
		p.s = p.s[2:]
		right, err := p.expr(prec + 1)
		if err != nil {
			return nil, err
		}
		left = &expression{tag: tag, children: []*expression{left, right}}
	}
	return left, nil
}
func (p *conditionParser) operand() (*expression, error) {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > 128 {
		return nil, invalid("operand nesting")
	}
	p.space()
	if p.s == "" {
		return nil, invalid("missing operand")
	}
	v := new(expression)
	if p.eat("{") {
		v.tag = 0x50
		for {
			if p.eat("}") {
				break
			}
			x, e := p.operand()
			if e != nil {
				return nil, e
			}
			v.children = append(v.children, x)
			if p.eat("}") {
				break
			}
			if !p.eat(",") {
				return nil, invalid("composite separator")
			}
		}
		return v, nil
	}
	if p.keyword("SID") {
		if !p.eat("(") {
			return nil, invalid("SID literal")
		}
		i := strings.IndexByte(p.s, ')')
		if i < 0 {
			return nil, invalid("SID literal")
		}
		sid, e := parseTrustee(strings.TrimSpace(p.s[:i]))
		if e != nil {
			return nil, e
		}
		p.s = p.s[i+1:]
		v.tag = 0x51
		v.data = sid.Bytes()
		return v, nil
	}
	if p.s[0] == '"' {
		p.s = p.s[1:]
		i := strings.IndexByte(p.s, '"')
		if i < 0 {
			return nil, invalid("quoted operand")
		}
		v.tag = 0x10
		v.text = p.s[:i]
		p.s = p.s[i+1:]
		return v, nil
	}
	if p.s[0] == '@' {
		p.s = p.s[1:]
		i := 0
		for i < len(p.s) && ident(p.s[i]) {
			i++
		}
		full := p.s[:i]
		p.s = p.s[i:]
		parts := strings.SplitN(full, ".", 2)
		if len(parts) != 2 || parts[1] == "" {
			return nil, invalid("attribute name")
		}
		switch strings.ToLower(parts[0]) {
		case "local":
			v.tag = 0xf8
		case "user":
			v.tag = 0xf9
		case "resource":
			v.tag = 0xfa
		case "device":
			v.tag = 0xfb
		default:
			return nil, invalid("attribute scope")
		}
		v.text = parts[1]
		return v, nil
	}
	if p.s[0] == '#' {
		p.s = p.s[1:]
		i := 0
		for i < len(p.s) && strings.ContainsRune("0123456789abcdefABCDEF", rune(p.s[i])) {
			i++
		}
		b, e := hex.DecodeString(p.s[:i])
		if e != nil {
			return nil, invalid("octet literal")
		}
		p.s = p.s[i:]
		v.tag = 0x18
		v.data = b
		return v, nil
	}
	i := 0
	for i < len(p.s) && strings.ContainsRune("0123456789abcdefABCDEFxX-+", rune(p.s[i])) {
		i++
	}
	if i == 0 {
		return nil, invalid("operand")
	}
	s := p.s[:i]
	p.s = p.s[i:]
	n, e := parseInteger(s)
	if e != nil {
		return nil, e
	}
	v.tag = 4
	v.data = binary.LittleEndian.AppendUint64(nil, uint64(n))
	sign := byte(3)
	if n < 0 {
		sign = 2
	}
	v.data = append(v.data, sign, 2)
	return v, nil
}
func parseInteger(s string) (int64, error) {
	base := 10
	if strings.HasPrefix(strings.TrimLeft(s, "-+"), "0x") || strings.HasPrefix(strings.TrimLeft(s, "-+"), "0X") {
		base = 0
	}
	n, e := strconv.ParseInt(s, base, 64)
	if e != nil {
		return 0, invalid("integer")
	}
	return n, nil
}
func utf16Bytes(s string) []byte {
	var b []byte
	for _, v := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, v)
	}
	return b
}
func utf16String(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", invalid("UTF-16 length")
	}
	v := make([]uint16, len(b)/2)
	for i := range v {
		v[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	for i := 0; i < len(v); i++ {
		if v[i] >= 0xd800 && v[i] <= 0xdbff {
			if i+1 == len(v) || v[i+1] < 0xdc00 || v[i+1] > 0xdfff {
				return "", invalid("UTF-16 surrogate")
			}
			i++
		} else if v[i] >= 0xdc00 && v[i] <= 0xdfff {
			return "", invalid("UTF-16 surrogate")
		}
	}
	return string(utf16.Decode(v)), nil
}
func (v *expression) encode() []byte {
	if v.tag >= 0x80 && v.tag < 0xf8 {
		var b []byte
		for _, c := range v.children {
			b = append(b, c.encode()...)
		}
		return append(b, v.tag)
	}
	b := []byte{v.tag}
	if v.tag == 4 {
		return append(b, v.data...)
	}
	data := v.data
	if v.tag == 0x10 || v.tag >= 0xf8 {
		data = utf16Bytes(v.text)
	}
	if v.tag == 0x50 {
		for _, c := range v.children {
			data = append(data, c.encode()...)
		}
	}
	b = binary.LittleEndian.AppendUint32(b, uint32(len(data)))
	return append(b, data...)
}

// ParseCondition compiles a conditional ACE expression to its artx bytecode.
func ParseCondition(s string) ([]byte, error) {
	if len(s) > 65536 || !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
		return nil, invalid("condition text")
	}
	p := conditionParser{s: s}
	v, e := p.expr(0)
	if e != nil {
		return nil, e
	}
	p.space()
	if p.s != "" {
		return nil, invalid("trailing condition input")
	}
	b := append([]byte("artx"), v.encode()...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b, nil
}
func opArity(tag byte) int {
	if tag == 0xa0 || tag == 0xa1 || tag >= 0x80 && tag <= 0x86 || tag == 0x88 || tag == 0x8e || tag == 0x8f {
		return 2
	}
	if tag == 0xa2 || tag == 0x87 || tag == 0x8d || tag >= 0x89 && tag <= 0x8c || tag >= 0x90 && tag <= 0x93 {
		return 1
	}
	return 0
}
func decodeOperand(b []byte, depth int) (*expression, int, error) {
	if len(b) == 0 || depth > 128 {
		return nil, 0, invalid("truncated operand")
	}
	v := &expression{tag: b[0]}
	if v.tag == 4 {
		if len(b) < 11 {
			return nil, 0, invalid("integer bytecode")
		}
		v.data = append([]byte(nil), b[1:11]...)
		return v, 11, nil
	}
	switch v.tag {
	case 0x10, 0x18, 0x50, 0x51, 0xf8, 0xf9, 0xfa, 0xfb:
	default:
		return nil, 0, invalid("operand token")
	}
	if len(b) < 5 {
		return nil, 0, invalid("operand length")
	}
	n := uint64(binary.LittleEndian.Uint32(b[1:]))
	if n > uint64(len(b)-5) {
		return nil, 0, invalid("operand bounds")
	}
	data := b[5 : 5+int(n)]
	var e error
	if v.tag == 0x10 || v.tag >= 0xf8 {
		v.text, e = utf16String(data)
	} else if v.tag == 0x50 {
		for len(data) > 0 {
			c, used, err := decodeOperand(data, depth+1)
			if err != nil {
				return nil, 0, err
			}
			v.children = append(v.children, c)
			data = data[used:]
		}
	} else {
		v.data = append([]byte(nil), data...)
		if v.tag == 0x51 {
			_, e = SIDFromBytes(data)
		}
	}
	return v, 5 + int(n), e
}
func expressionText(v *expression, parent int) string {
	var s string
	prec := 4
	switch v.tag {
	case 4:
		s = strconv.FormatInt(int64(binary.LittleEndian.Uint64(v.data)), 10)
	case 0x10:
		s = "\"" + v.text + "\""
	case 0x18:
		s = "#" + hex.EncodeToString(v.data)
	case 0x51:
		sid, _ := SIDFromBytes(v.data)
		s = "SID(" + formatTrustee(sid) + ")"
	case 0x50:
		parts := []string{}
		for _, c := range v.children {
			parts = append(parts, expressionText(c, 0))
		}
		s = "{" + strings.Join(parts, ", ") + "}"
	case 0xf8, 0xf9, 0xfa, 0xfb:
		s = "@" + []string{"Local", "User", "Resource", "Device"}[v.tag-0xf8] + "." + v.text
	case 0xa0, 0xa1:
		prec = 2
		op := " && "
		if v.tag == 0xa1 {
			prec = 1
			op = " || "
		}
		s = expressionText(v.children[0], prec) + op + expressionText(v.children[1], prec)
	case 0xa2:
		prec = 3
		s = "!" + expressionText(v.children[0], prec)
	default:
		for _, o := range comparisons {
			if byte(o.value) == v.tag {
				s = expressionText(v.children[0], 0) + " " + o.word + " " + expressionText(v.children[1], 0)
			}
		}
		for _, o := range unaryOps {
			if byte(o.value) == v.tag {
				s = o.word + " " + expressionText(v.children[0], 0)
			}
		}
	}
	if prec < parent {
		return "(" + s + ")"
	}
	return s
}

// FormatCondition validates postfix bytecode and renders an SDDL expression.
func FormatCondition(b []byte) (string, error) {
	if len(b) < 4 || string(b[:4]) != "artx" || len(b) > 65536 {
		return "", invalid("artx header")
	}
	b = b[4:]
	var stack []*expression
	for len(b) > 0 {
		tag := b[0]
		if tag == 0 {
			for _, v := range b {
				if v != 0 {
					return "", invalid("nonterminal padding")
				}
			}
			break
		}
		if n := opArity(tag); n > 0 {
			if len(stack) < n {
				return "", invalid("condition stack underflow")
			}
			children := append([]*expression(nil), stack[len(stack)-n:]...)
			height := 1
			for _, c := range children {
				if c.height+1 > height {
					height = c.height + 1
				}
			}
			if height > 128 {
				return "", invalid("condition nesting")
			}
			stack = stack[:len(stack)-n]
			for _, c := range children {
				isCondition := opArity(c.tag) != 0
				wantCondition := tag >= 0xa0
				if isCondition != wantCondition {
					return "", invalid("condition operand type")
				}
			}
			stack = append(stack, &expression{tag: tag, children: children, height: height})
			b = b[1:]
		} else {
			v, n, e := decodeOperand(b, 0)
			if e != nil {
				return "", e
			}
			stack = append(stack, v)
			b = b[n:]
		}
		if len(stack) > 1024 {
			return "", invalid("condition stack limit")
		}
	}
	if len(stack) != 1 || opArity(stack[0].tag) == 0 {
		return "", invalid("condition result")
	}
	s := expressionText(stack[0], 0)
	if !utf8.ValidString(s) {
		return "", fmt.Errorf("%w", invalid("condition encoding"))
	}
	if _, e := ParseCondition(s); e != nil {
		return "", invalid("condition cannot be represented as SDDL")
	}
	return s, nil
}
