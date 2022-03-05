package utils

import (
	"fmt"
	"reflect"
	"strings"
)

func getStructureInfo(data interface{}) ([]string, []string) {
	header := make([]string, 0)
	values := make([]string, 0)

	v := reflect.ValueOf(data)

	if v.Kind() != reflect.Struct {
		panic(fmt.Errorf("argument must be a struct not a %q", v.Kind().String()))
	}

	t := v.Type()
	for j := 0; j < t.NumField(); j++ {
		header = append(header, t.Field(j).Name)

		currentValue := ""

		switch v.Field(j).Kind() {
		case reflect.String:
			currentValue = v.Field(j).Interface().(string)
		case reflect.Uint16, reflect.Uint32, reflect.Uint64:
			currentValue = fmt.Sprintf("%d", uint64(v.Field(j).Uint()))
		default:
			panic(fmt.Errorf("cannot get string from %q", v.Field(j).Kind().String()))
		}

		values = append(values, currentValue)
	}

	return header, values
}

// Sprintf but with []string as argument (instead of []interface)
func sprintfWithStrings(s string, args []string) string {
	vals := make([]interface{}, len(args))
	for i, v := range args {
		vals[i] = v
	}

	return fmt.Sprintf(s, vals...)
}

func PrintTable(data interface{}) string {
	var header []string
	headerSize := make([]int, 0)
	values := make([][]string, 0)

	dataValue := reflect.ValueOf(data)

	if dataValue.Kind() == reflect.Slice {
		for i := 0; i < dataValue.Len(); i++ {
			val := dataValue.Index(i).Interface()
			keys, currentValues := getStructureInfo(val)

			values = append(values, currentValues)

			if i == 0 {
				header = keys
			}

			for j, currentValue := range currentValues {
				if i == 0 {
					headerSize = append(headerSize, len(keys[j]))
				}

				if headerSize[j] < len(currentValue) {
					headerSize[j] = len(currentValue)
				}
			}
		}
	} else if dataValue.Kind() == reflect.Struct {
		keys, currentValues := getStructureInfo(data)

		header = keys
		values = append(values, currentValues)
		for j, currentValue := range currentValues {
			if len(keys[j]) < len(currentValue) {
				headerSize = append(headerSize, len(currentValue))
			} else {
				headerSize = append(headerSize, len(keys[j]))
			}
		}
	} else {
		panic(fmt.Errorf("argument must be a slice not %q", dataValue.Kind().String()))
	}

	output := ""
	separator := make([]string, 0)
	template := "|"
	for _, size := range headerSize {
		template += fmt.Sprintf(" %%%ds |", size)
		separator = append(separator, strings.Repeat("-", size))
	}
	template += "\n"

	output += sprintfWithStrings(template, header)
	output += sprintfWithStrings(template, separator)
	for _, v := range values {
		output += sprintfWithStrings(template, v)
	}

	return output
}
