package utils

import (
	"encoding/json"
)

func PrettyfyJSON(data interface{}) (string, error) {
	buff, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return "", err
	}

	return string(buff), nil
}
