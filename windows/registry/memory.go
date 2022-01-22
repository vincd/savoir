package registry

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/vincd/savoir/utils"
)

type MemoryHive struct {
	data []byte
}

type MemoryKey struct {
	hive MemoryHive
	node RegistryNodeKey
}

type RegistryNodeKeyWithoutName struct {
	Id            [2]byte
	Flags         uint16
	T1            uint32
	T2            uint32
	Unk1          uint32
	Parent_off    uint32
	Subkey_num    uint32
	Unk2          uint32
	Lf_off        uint32
	Unk3          uint32
	Value_cnt     uint32
	Value_off     uint32
	Sk_off        uint32
	Classname_off uint32
	Unk41         uint32
	Unk42         uint32
	Unk43         uint32
	Unk44         uint32
	Unk5          uint32
	Name_len      uint16
	Classname_len uint16
}

type RegistryNodeKey struct {
	RegistryNodeKeyWithoutName
	KeyName   string
	ClassName string
}

type RegistryFastLeafWithoutRecords struct {
	Id     [2]byte
	KeyNum uint16
}

type RegistryFastLeaf struct {
	RegistryFastLeafWithoutRecords
	HashRecords []RegistryHashRecord
}

type RegistryHashRecord struct {
	NamedKeyOffset uint32
	Hash           [4]byte
}

type RegistryValueKeyWithoutName struct {
	Id        [2]byte
	Name_len  uint16
	Data_len  uint32
	Data_off  uint32
	Data_type uint32
	Flag      uint16
	Unk1      uint16
}

type RegistryValueKey struct {
	RegistryValueKeyWithoutName
	ValueName string
}

func NewMemoryHive(system string) (MemoryHive, error) {
	data, err := ioutil.ReadFile(system)
	if err != nil {
		return MemoryHive{}, err
	}

	h := MemoryHive{
		data: data,
	}

	return h, nil
}

func (h MemoryHive) getRootKey() (MemoryKey, error) {
	rootNode, err := h.readNK(0x20)
	if err != nil {
		return MemoryKey{}, err
	}

	rootKey := MemoryKey{
		hive: h,
		node: *rootNode,
	}

	return rootKey, nil
}

func (h MemoryHive) readNK(offset uint32) (*RegistryNodeKey, error) {
	buf := bytes.NewBuffer(h.data[0x1000+offset+4 : 0x1000+offset+4+77])
	obj := &RegistryNodeKeyWithoutName{}
	err := binary.Read(buf, binary.LittleEndian, obj)
	if err != nil {
		return nil, err
	}

	keyName := string(h.data[0x1000+offset+4+76 : 0x1000+offset+4+76+uint32(obj.Name_len)])
	className, err := utils.UTF16DecodeFromBytes(h.data[0x1000+4+obj.Classname_off : 0x1000+4+obj.Classname_off+uint32(obj.Classname_len)])
	if err != nil {
		return nil, err
	}

	nk := &RegistryNodeKey{
		RegistryNodeKeyWithoutName: *obj,
		KeyName:                    keyName,
		ClassName:                  string(className),
	}

	return nk, nil
}

func (h MemoryHive) readFastLeaf(offset uint32) (*RegistryFastLeaf, error) {
	buf := bytes.NewBuffer(h.data[0x1000+offset+4 : 0x1000+offset+4+4])
	obj := &RegistryFastLeafWithoutRecords{}
	err := binary.Read(buf, binary.LittleEndian, obj)
	if err != nil {
		return nil, err
	}

	lf := &RegistryFastLeaf{
		RegistryFastLeafWithoutRecords: *obj,
		HashRecords:                    make([]RegistryHashRecord, 0),
	}

	for i := uint16(0); i < lf.KeyNum; i++ {
		hr, err := h.readHR(offset+4+4, i)
		if err != nil {
			return nil, err
		}

		lf.HashRecords = append(lf.HashRecords, *hr)
	}

	return lf, nil
}

func (h MemoryHive) readHR(offset uint32, index uint16) (*RegistryHashRecord, error) {
	offset += uint32(index) * 8
	buf := bytes.NewBuffer(h.data[0x1000+offset : 0x1000+offset+8])
	obj := &RegistryHashRecord{}
	err := binary.Read(buf, binary.LittleEndian, obj)
	if err != nil {
		return nil, err
	}

	return obj, nil
}

func (h MemoryHive) readValueKey(offset uint32) (*RegistryValueKey, error) {
	buf := bytes.NewBuffer(h.data[0x1000+4+offset : 0x1000+4+offset+20])
	obj := &RegistryValueKeyWithoutName{}
	err := binary.Read(buf, binary.LittleEndian, obj)
	if err != nil {
		return nil, err
	}

	valueName := string(h.data[0x1000+4+offset+20 : 0x1000+4+offset+20+uint32(obj.Name_len)])
	vk := &RegistryValueKey{
		RegistryValueKeyWithoutName: *obj,
		ValueName:                   valueName,
	}

	return vk, nil
}

// Get the NodeKey from a path
func (h MemoryHive) OpenKey(path string) (HiveKey, error) {
	slice_path := strings.Split(path, "\\")
	currentKey, err := h.getRootKey()
	if err != nil {
		return MemoryKey{}, err
	}

	for _, name := range slice_path {
		nodeChildren, err := currentKey.EnumKey()
		if err != nil {
			return MemoryKey{}, err
		}

		isFound := false
		for _, node := range nodeChildren {
			child := (node).(MemoryKey)
			if child.node.KeyName == name {
				currentKey = child
				isFound = true
				break
			}
		}

		if !isFound {
			return MemoryKey{}, fmt.Errorf("Cannot open key %s in the node %s.", slice_path, currentKey.node.KeyName)
		}
	}

	return currentKey, nil
}

// List children NodeKey of a NodeKey
func (key MemoryKey) EnumKey() ([]HiveKey, error) {
	lf, err := key.hive.readFastLeaf(key.node.Lf_off)
	if err != nil {
		return nil, err
	}

	NKs := make([]HiveKey, 0)
	for _, hr := range lf.HashRecords {
		nk, err := key.hive.readNK(hr.NamedKeyOffset)
		if err != nil {
			return nil, err
		}

		NKs = append(NKs, MemoryKey{
			hive: key.hive,
			node: *nk,
		})
	}

	return NKs, nil
}

// Query the value of a NodeKey
func (key MemoryKey) QueryValue(value string) ([]byte, error) {
	for i := uint32(0); i < key.node.Value_cnt; i++ {
		offset := key.node.Value_off + 4*i
		offset_vk := binary.LittleEndian.Uint32(key.hive.data[0x1000+offset+4 : 0x1000+offset+4+4])

		vk, err := key.hive.readValueKey(offset_vk)
		if err != nil {
			return nil, err
		}

		if vk.ValueName == value || (vk.Flag&1) == 0 {
			data_len := vk.Data_len & 0x0000FFFF

			if data_len < 5 {
				data := make([]byte, 4)
				binary.LittleEndian.PutUint32(data, vk.Data_off)
				return data, nil
			} else {
				return key.hive.data[0x1000+4+vk.Data_off : 0x1000+4+vk.Data_off+data_len], nil
			}
		}
	}

	return nil, fmt.Errorf("Cannot query value %s", value)
}

func (key MemoryKey) ClassName() (string, error) {
	return key.node.ClassName, nil
}

func (key MemoryKey) Name() string {
	return key.node.KeyName
}

func (key MemoryKey) Close() error {
	return nil
}
