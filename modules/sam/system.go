package sam

import (
	"encoding/hex"
	"fmt"

	"github.com/vincd/savoir/windows/registry"
)

type SystemHive struct {
	registry.Hive
}

// Get Current Control Set from "\Select\Current" or "\Select\Default"
func (h *SystemHive) getCurrentControlSet() (string, error) {
	node, err := h.OpenKey("Select")
	if err != nil {
		return "", err
	}

	for _, name := range []string{"Current", "Default"} {
		vk, err := node.QueryValue(name)
		if err != nil {
			return "", err
		}

		currentControlSet := fmt.Sprintf("ControlSet%03d\\Control\\Lsa\\", vk[0])

		return currentControlSet, nil
	}

	return "", fmt.Errorf("Cannot find Current ControlSet")
}

// Return the System key (bootkey)
func (h *SystemHive) GetSystemKey() ([]byte, error) {
	// We need the Current Control Set
	currentControlSet, err := h.getCurrentControlSet()
	if err != nil {
		return nil, err
	}

	lsa_keys := []string{"JD", "Skew1", "GBG", "Data"}
	encodedKey := ""

	for _, k := range lsa_keys {
		vk, err := h.OpenKey(currentControlSet + k)
		if err != nil {
			return nil, err
		}

		className, err := vk.ClassName()
		if err != nil {
			return nil, err
		}

		encodedKey += className
	}

	decodedKey, err := hex.DecodeString(encodedKey)
	if err != nil {
		return nil, err
	}

	permutation_matrix := [0x10]byte{0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7}
	sysKey := make([]byte, 0)
	for i := 0; i < len(decodedKey); i++ {
		sysKey = append(sysKey, decodedKey[permutation_matrix[i]])
	}

	return sysKey, nil
}
