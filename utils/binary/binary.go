// From: https://golang.org/src/encoding/binary/binary.go?m=text
package binary

import (
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"sync"
)

// A ByteOrder specifies how to convert byte sequences into
// 16-, 32-, or 64-bit unsigned integers.
type ByteOrder interface {
	Uint16([]byte) uint16
	Uint32([]byte) uint32
	Uint64([]byte) uint64
	PutUint16([]byte, uint16)
	PutUint32([]byte, uint32)
	PutUint64([]byte, uint64)
	String() string
}

// LittleEndian is the little-endian implementation of ByteOrder.
var LittleEndian littleEndian

type littleEndian struct{}

func (littleEndian) Uint16(b []byte) uint16 {
	_ = b[1] // bounds check hint to compiler; see golang.org/issue/14808
	return uint16(b[0]) | uint16(b[1])<<8
}

func (littleEndian) PutUint16(b []byte, v uint16) {
	_ = b[1] // early bounds check to guarantee safety of writes below
	b[0] = byte(v)
	b[1] = byte(v >> 8)
}

func (littleEndian) Uint32(b []byte) uint32 {
	_ = b[3] // bounds check hint to compiler; see golang.org/issue/14808
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func (littleEndian) PutUint32(b []byte, v uint32) {
	_ = b[3] // early bounds check to guarantee safety of writes below
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

func (littleEndian) Uint64(b []byte) uint64 {
	_ = b[7] // bounds check hint to compiler; see golang.org/issue/14808
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

func (littleEndian) PutUint64(b []byte, v uint64) {
	_ = b[7] // early bounds check to guarantee safety of writes below
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	b[4] = byte(v >> 32)
	b[5] = byte(v >> 40)
	b[6] = byte(v >> 48)
	b[7] = byte(v >> 56)
}

func (littleEndian) String() string { return "LittleEndian" }

func (littleEndian) GoString() string { return "binary.LittleEndian" }

// Read reads structured binary data from r into data.
// Data must be a pointer to a fixed-size value or a slice
// of fixed-size values.
// Bytes read from r are decoded using the specified byte order
// and written to successive fields of the data.
// When decoding boolean values, a zero byte is decoded as false, and
// any other non-zero byte is decoded as true.
// When reading into structs, the field data for fields with
// blank (_) field names is skipped; i.e., blank field names
// may be used for padding.
// When reading into a struct, all non-blank fields must be exported
// or Read may panic.
//
// The error is EOF only if no bytes were read.
// If an EOF happens after reading some but not all the bytes,
// Read returns ErrUnexpectedEOF.
func Read(r io.Reader, order ByteOrder, is64 bool, data interface{}) error {
	// Fast path for basic types and slices.
	if n := intDataSize(data); n != 0 {
		bs := make([]byte, n)
		if _, err := io.ReadFull(r, bs); err != nil {
			return err
		}
		switch data := data.(type) {
		case *bool:
			*data = bs[0] != 0
		case *int8:
			*data = int8(bs[0])
		case *uint8:
			*data = bs[0]
		case *int16:
			*data = int16(order.Uint16(bs))
		case *uint16:
			*data = order.Uint16(bs)
		case *int32:
			*data = int32(order.Uint32(bs))
		case *uint32:
			*data = order.Uint32(bs)
		case *int64:
			*data = int64(order.Uint64(bs))
		case *uint64:
			*data = order.Uint64(bs)
		case *float32:
			*data = math.Float32frombits(order.Uint32(bs))
		case *float64:
			*data = math.Float64frombits(order.Uint64(bs))
		case []bool:
			for i, x := range bs { // Easier to loop over the input for 8-bit values.
				data[i] = x != 0
			}
		case []int8:
			for i, x := range bs {
				data[i] = int8(x)
			}
		case []uint8:
			copy(data, bs)
		case []int16:
			for i := range data {
				data[i] = int16(order.Uint16(bs[2*i:]))
			}
		case []uint16:
			for i := range data {
				data[i] = order.Uint16(bs[2*i:])
			}
		case []int32:
			for i := range data {
				data[i] = int32(order.Uint32(bs[4*i:]))
			}
		case []uint32:
			for i := range data {
				data[i] = order.Uint32(bs[4*i:])
			}
		case []int64:
			for i := range data {
				data[i] = int64(order.Uint64(bs[8*i:]))
			}
		case []uint64:
			for i := range data {
				data[i] = order.Uint64(bs[8*i:])
			}
		case []float32:
			for i := range data {
				data[i] = math.Float32frombits(order.Uint32(bs[4*i:]))
			}
		case []float64:
			for i := range data {
				data[i] = math.Float64frombits(order.Uint64(bs[8*i:]))
			}
		default:
			n = 0 // fast path doesn't apply
		}
		if n != 0 {
			return nil
		}
	}

	// Fallback to reflect-based decoding.
	v := reflect.ValueOf(data)
	size := -1
	switch v.Kind() {
	case reflect.Ptr:
		v = v.Elem()
		size = dataSize(v, is64)
	case reflect.Slice:
		size = dataSize(v, is64)
	}
	if size < 0 {
		return errors.New("binary.Read: invalid type " + reflect.TypeOf(data).String())
	}
	d := &decoder{order: order, buf: make([]byte, size)}
	if _, err := io.ReadFull(r, d.buf); err != nil {
		return err
	}
	d.value(v, is64)
	return nil
}

// Size returns how many bytes Write would generate to encode the value v, which
// must be a fixed-size value or a slice of fixed-size values, or a pointer to such data.
// If v is neither of these, Size returns -1.
func Size(v interface{}, is64 bool) int {
	return dataSize(reflect.Indirect(reflect.ValueOf(v)), is64)
}

var structSize sync.Map // map[reflect.Type]int

// dataSize returns the number of bytes the actual data represented by v occupies in memory.
// For compound structures, it sums the sizes of the elements. Thus, for instance, for a slice
// it returns the length of the slice times the element size and does not count the memory
// occupied by the header. If the type of v is not acceptable, dataSize returns -1.
func dataSize(v reflect.Value, is64 bool) int {
	switch v.Kind() {
	case reflect.Slice:
		if s := sizeof(v.Type().Elem(), is64); s >= 0 {
			return s * v.Len()
		}
		return -1

	case reflect.Struct:
		t := v.Type()
		if size, ok := structSize.Load(t); ok {
			return size.(int)
		}
		size := sizeof(t, is64)
		structSize.Store(t, size)
		return size

	default:
		return sizeof(v.Type(), is64)
	}
}

func getAligment(is64 bool) int {
	if is64 {
		return 8
	} else {
		return 4
	}
}

func Sizeof(t reflect.Type, is64 bool) int {
	return sizeof(t, is64)
}

// sizeof returns the size >= 0 of variables for the given type or -1 if the type is not acceptable.
func sizeof(t reflect.Type, is64 bool) int {
	if t == pointerType {
		if is64 {
			return 8
		} else {
			return 4
		}
	}

	alignment := getAligment(is64)

	switch t.Kind() {
	case reflect.Array:
		if s := sizeof(t.Elem(), is64); s >= 0 {
			return s * t.Len()
		}

	case reflect.Struct:
		sum := 0
		for i, n := 0, t.NumField(); i < n; i++ {
			// The field named "_" indicates an aligment
			if t.Field(i).Name == "_" {
				alignTag := t.Field(i).Tag.Get("align")
				fieldAligment := alignment
				if alignTag == "8" && !is64 {
					fieldAligment = 8
				}
				offset := sum % fieldAligment
				sum += (fieldAligment - offset) % fieldAligment
			} else {
				s := sizeof(t.Field(i).Type, is64)
				if s < 0 {
					return -1
				}
				sum += s
			}
		}
		return sum

	case reflect.Bool,
		reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128:
		return int(t.Size())
	}

	return -1
}

type coder struct {
	order  ByteOrder
	buf    []byte
	offset int
}

type decoder coder

func (d *decoder) bool() bool {
	x := d.buf[d.offset]
	d.offset++
	return x != 0
}

func (d *decoder) uint8() uint8 {
	x := d.buf[d.offset]
	d.offset++
	return x
}

func (d *decoder) uint16() uint16 {
	x := d.order.Uint16(d.buf[d.offset : d.offset+2])
	d.offset += 2
	return x
}

func (d *decoder) uint32() uint32 {
	x := d.order.Uint32(d.buf[d.offset : d.offset+4])
	d.offset += 4
	return x
}

func (d *decoder) uint64() uint64 {
	x := d.order.Uint64(d.buf[d.offset : d.offset+8])
	d.offset += 8
	return x
}

func (d *decoder) int8() int8 { return int8(d.uint8()) }

func (d *decoder) int16() int16 { return int16(d.uint16()) }

func (d *decoder) int32() int32 { return int32(d.uint32()) }

func (d *decoder) int64() int64 { return int64(d.uint64()) }

func (d *decoder) value(v reflect.Value, is64 bool) {
	if v.Type() == pointerType {
		if is64 {
			v.SetUint(d.uint64())
		} else {
			v.SetUint(uint64(d.uint32()))
		}
		return
	}

	switch v.Kind() {
	case reflect.Array:
		l := v.Len()
		for i := 0; i < l; i++ {
			d.value(v.Index(i), is64)
		}

	case reflect.Struct:
		t := v.Type()
		l := v.NumField()
		// fmt.Printf("\nRead new structure %s\n----------------------------\n", t)
		currentSize := 0
		alignment := getAligment(is64)
		for i := 0; i < l; i++ {
			// fmt.Printf("Value:: Field:%s %d (%d)\n", t.Field(i).Name, dataSize(v.Field(i), is64), currentSize)
			// Note: Calling v.CanSet() below is an optimization.
			// It would be sufficient to check the field name,
			// but creating the StructField info for each field is
			// costly (run "go test -bench=ReadStruct" and compare
			// results when making changes to this code).
			if v := v.Field(i); v.CanSet() || t.Field(i).Name != "_" {
				d.value(v, is64)
				currentSize += dataSize(v, is64)
			} else {
				alignTag := t.Field(i).Tag.Get("align")
				fieldAligment := alignment
				if alignTag == "8" && !is64 {
					fieldAligment = 8
				}
				offset := currentSize % fieldAligment
				// fmt.Printf("Skip for aligment %d %d %d\n", currentSize, currentSize % fieldAligment, (fieldAligment - offset) % fieldAligment)
				// d.skip(v, is64)
				d.offset += (fieldAligment - offset) % fieldAligment
				currentSize += (fieldAligment - offset) % fieldAligment
			}
		}
		// fmt.Printf("----------------------------\n\n")

	case reflect.Slice:
		l := v.Len()
		for i := 0; i < l; i++ {
			d.value(v.Index(i), is64)
		}

	case reflect.Bool:
		v.SetBool(d.bool())

	case reflect.Int8:
		v.SetInt(int64(d.int8()))
	case reflect.Int16:
		v.SetInt(int64(d.int16()))
	case reflect.Int32:
		v.SetInt(int64(d.int32()))
	case reflect.Int64:
		v.SetInt(d.int64())

	case reflect.Uint8:
		v.SetUint(uint64(d.uint8()))
	case reflect.Uint16:
		v.SetUint(uint64(d.uint16()))
	case reflect.Uint32:
		v.SetUint(uint64(d.uint32()))
	case reflect.Uint64:
		v.SetUint(d.uint64())

	case reflect.Float32:
		v.SetFloat(float64(math.Float32frombits(d.uint32())))
	case reflect.Float64:
		v.SetFloat(math.Float64frombits(d.uint64()))

	case reflect.Complex64:
		v.SetComplex(complex(
			float64(math.Float32frombits(d.uint32())),
			float64(math.Float32frombits(d.uint32())),
		))
	case reflect.Complex128:
		v.SetComplex(complex(
			math.Float64frombits(d.uint64()),
			math.Float64frombits(d.uint64()),
		))
	}
}

func (d *decoder) skip(v reflect.Value, is64 bool) {
	d.offset += dataSize(v, is64)
}

// intDataSize returns the size of the data required to represent the data when encoded.
// It returns zero if the type cannot be implemented by the fast path in Read or Write.
func intDataSize(data interface{}) int {
	switch data := data.(type) {
	case bool, int8, uint8, *bool, *int8, *uint8:
		return 1
	case []bool:
		return len(data)
	case []int8:
		return len(data)
	case []uint8:
		return len(data)
	case int16, uint16, *int16, *uint16:
		return 2
	case []int16:
		return 2 * len(data)
	case []uint16:
		return 2 * len(data)
	case int32, uint32, *int32, *uint32:
		return 4
	case []int32:
		return 4 * len(data)
	case []uint32:
		return 4 * len(data)
	case int64, uint64, *int64, *uint64:
		return 8
	case []int64:
		return 8 * len(data)
	case []uint64:
		return 8 * len(data)
	case float32, *float32:
		return 4
	case float64, *float64:
		return 8
	case []float32:
		return 4 * len(data)
	case []float64:
		return 8 * len(data)
	}
	return 0
}

func GetStructureFieldOffset(t reflect.Type, fieldName string, is64 bool) int64 {
	l := t.NumField()
	fieldOffset := 0

	alignment := getAligment(is64)

	for i := 0; i < l; i++ {
		if t.Field(i).Name == fieldName {
			return int64(fieldOffset)
		} else {
			if t.Field(i).Name != "_" {
				fieldOffset += sizeof(t.Field(i).Type, is64)
			} else {
				alignTag := t.Field(i).Tag.Get("align")
				fieldAligment := alignment
				if alignTag == "8" && !is64 {
					fieldAligment = 8
				}
				offset := fieldOffset % fieldAligment
				fieldOffset += (fieldAligment - offset) % fieldAligment
			}
		}
	}

	panic(fmt.Sprintf("Cannot get field offset %s of structure %s.", fieldName, t))
}

func DumpStructureFieldsOffsets(t reflect.Type, is64 bool) {
	l := t.NumField()
	fieldOffset := 0

	alignment := getAligment(is64)

	s := fmt.Sprintf("Structure: %s with aligment %d\n", t, alignment)
	for i := 0; i < l; i++ {
		if t.Field(i).Name != "_" {
			size := sizeof(t.Field(i).Type, is64)
			s += fmt.Sprintf("  - [%04d] %s (%d)\n", fieldOffset, t.Field(i).Name, size)
			fieldOffset += sizeof(t.Field(i).Type, is64)
		} else {
			alignTag := t.Field(i).Tag.Get("align")
			fieldAligment := alignment
			if alignTag == "8" && !is64 {
				fieldAligment = 8
			}
			offset := fieldOffset % fieldAligment
			s += fmt.Sprintf("  - [%04d] (aligment %s) (%d)\n", fieldOffset, t.Field(i).Tag.Get("align"), offset)
			fieldOffset += (fieldAligment - offset) % fieldAligment
		}
	}

	fmt.Printf(s)
}
