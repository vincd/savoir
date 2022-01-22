package krb5

import (
	"fmt"
	"reflect"
	"time"

	"github.com/vincd/savoir/utils/asn1"
)

// Returns the microseconds on the time
func microseconds(t time.Time) int {
	return int((t.UnixNano() / int64(time.Microsecond)) - (t.Unix() * 1e6))
}

// Returns data structure tag
func getStructureTag(b []byte) byte {
	if len(b) == 0 {
		return 0
	}

	return b[0] & KERB_BER_APPLICATION_MASK
}

// Unmarshall a structure and check if the message type matchs
func unmarshalMessage(b []byte, val interface{}, messageType int) error {
	if _, err := asn1.UnmarshalWithParams(b, val, fmt.Sprintf("application,explicit,tag:%d", messageType)); err != nil {
		return fmt.Errorf("Cannot Unmarshal message: %s", err)
	}

	elem := reflect.ValueOf(val).Elem()
	if elem.Kind() == reflect.Struct {
		msgTypeField := elem.FieldByName("MsgType")
		if msgTypeField.IsValid() {
			msgTypeValue := int(msgTypeField.Int())
			if msgTypeValue != messageType {
				return fmt.Errorf("The Message Type doesn't match: %d != %d", msgTypeValue, messageType)
			}
		}
	}

	return nil
}
