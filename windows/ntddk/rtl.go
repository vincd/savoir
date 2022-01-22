package ntddk

import (
	"github.com/vincd/savoir/utils"
	"github.com/vincd/savoir/utils/binary"
)

type RtlBalancedLinks struct {
	Parent     binary.Pointer
	LeftChild  binary.Pointer
	RightChild binary.Pointer
	Balance    byte
	Reserved   [3]uint8
	_          uint32
}

type RtlAvlTable struct {
	BalancedRoot               RtlBalancedLinks
	OrderedPointer             binary.Pointer
	WhichOrderedElement        uint64
	NumberGenericTableElements uint64
	DepthOfTree                uint64
	Unk1                       uint64
	RestartKey                 binary.Pointer
	DeleteCount                uint64
	Unk2                       uint64
	CompareRoutine             binary.Pointer
	AllocateRoutine            binary.Pointer
	FreeRoutine                binary.Pointer
	TableContext               binary.Pointer
}

func WalkAVL(l utils.MemoryReader, nodePtr binary.Pointer) ([]binary.Pointer, error) {
	node := &RtlAvlTable{}
	if err := l.ReadStructure(nodePtr, node); err != nil {
		return nil, err
	}

	currentList := make([]binary.Pointer, 0)

	if node.OrderedPointer != 0 {
		currentList = append(currentList, node.OrderedPointer)

		if node.BalancedRoot.LeftChild != 0 {
			leftList, err := WalkAVL(l, node.BalancedRoot.LeftChild)
			if err != nil {
				return nil, err
			}
			currentList = append(currentList, leftList...)
		}

		if node.BalancedRoot.RightChild != 0 {
			rightList, err := WalkAVL(l, node.BalancedRoot.RightChild)
			if err != nil {
				return nil, err
			}
			currentList = append(currentList, rightList...)
		}
	}

	return currentList, nil
}

func (t *RtlAvlTable) Walk(l utils.MemoryReader) ([]binary.Pointer, error) {
	if t.BalancedRoot.RightChild == 0 {
		return nil, nil
	}

	ptrList, err := WalkAVL(l, t.BalancedRoot.RightChild)
	if err != nil {
		return nil, err
	}

	return ptrList, nil
}
