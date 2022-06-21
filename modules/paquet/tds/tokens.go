package tds

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/vincd/savoir/utils"
)

type TdsToken interface {
	GetTokenType() uint8
}

type TdsTokenWithType struct {
	TokenType uint8
}

func (t *TdsTokenWithType) GetTokenType() uint8 {
	return t.TokenType
}

type TdsTokens struct {
	Tokens []TdsToken
}

func NewTdsTokens(tds *TdsPacket) (*TdsTokens, error) {
	data := tds.Data
	tokens := &TdsTokens{Tokens: make([]TdsToken, 0)}

	// keep a reference of the columns metadata to parse rows
	var tokenCols *TdsTokenCols

	for len(data) > 0 {
		tokenId := uint8(data[0])
		data = data[1:]

		switch tokenId {
		case TDS_TOKEN_ENVCHANGE:
			n, tokenEnvChange, err := NewTdsTokenEnvChange(tokenId, data)
			if err != nil {
				return nil, fmt.Errorf("cannot read Token EnvChange: %s", err)
			}
			data = data[n:]
			tokens.Tokens = append(tokens.Tokens, tokenEnvChange)

		case TDS_TOKEN_INFO, TDS_TOKEN_ERROR:
			n, tokenInfo, err := NewTdsTokenInfo(tokenId, data)
			if err != nil {
				return nil, fmt.Errorf("cannot read Token Error: %s", err)
			}
			data = data[n:]
			tokens.Tokens = append(tokens.Tokens, tokenInfo)

		case TDS_TOKEN_LOGINACK:
			n, tokenLoginAck, err := NewTdsTokenLoginAck(tokenId, data)
			if err != nil {
				return nil, fmt.Errorf("cannot read Token LoginAck: %s", err)
			}
			data = data[n:]
			tokens.Tokens = append(tokens.Tokens, tokenLoginAck)

		case TDS_TOKEN_COLMETADATA:
			n, cols, err := NewTdsTokenCols(tokenId, data)
			if err != nil {
				return nil, err
			}
			data = data[n:]
			tokenCols = cols
			tokens.Tokens = append(tokens.Tokens, tokenCols)

		case TDS_TOKEN_ROW:
			n, tokenRow, err := NewTdsTokenRow(tokenId, data, tokenCols)
			if err != nil {
				return nil, fmt.Errorf("cannot read Token Row: %s", err)
			}
			data = data[n:]
			tokens.Tokens = append(tokens.Tokens, tokenRow)

		case TDS_TOKEN_RETURNSTATUS:
			n, tokenReturnValue, err := NewTdsTokenReturnValue(tokenId, data)
			if err != nil {
				return nil, fmt.Errorf("cannot read Token ReturnValue: %s", err)
			}
			data = data[n:]
			tokens.Tokens = append(tokens.Tokens, tokenReturnValue)

		case TDS_TOKEN_DONE, TDS_TOKEN_DONEINPROC, TDS_TOKEN_DONEPROC:
			n, tokenDone, err := NewTdsTokenDone(tokenId, data)
			if err != nil {
				return nil, fmt.Errorf("cannot read Token Done: %s", err)
			}
			data = data[n:]
			tokens.Tokens = append(tokens.Tokens, tokenDone)

		default:
			return nil, fmt.Errorf("unknow reply token ID 0x%x", tokenId)
		}

	}

	return tokens, nil
}

func (t *TdsTokens) GetWithType(tokenType uint8) []TdsToken {
	tokens := make([]TdsToken, 0)

	for _, token := range t.Tokens {
		if token.GetTokenType() == tokenType {
			tokens = append(tokens, token)
		}
	}

	return tokens
}

func (t *TdsTokens) PrintInfos() {
	for _, token := range t.Tokens {
		switch token.GetTokenType() {
		case TDS_TOKEN_ENVCHANGE:
			tokenEnvChange := token.(*TdsTokenEnvChange)

			if tokenEnvChange.Env.Type == TDS_ENVCHANGE_DATABASE {
				newValueLength := uint8(tokenEnvChange.Env.Data[0])
				newValue := tokenEnvChange.Env.Data[1 : 1+newValueLength*2]
				oldValueLength := uint8(tokenEnvChange.Env.Data[1+newValueLength*2])
				oldValue := tokenEnvChange.Env.Data[2+newValueLength*2 : 2+newValueLength*2+oldValueLength*2]

				fmt.Printf("[*] [Env] Change database from %s to %s\n", oldValue, newValue)
			} else if tokenEnvChange.Env.Type == TDS_ENVCHANGE_LANGUAGE {
				newValueLength := uint8(tokenEnvChange.Env.Data[0])
				newValue := tokenEnvChange.Env.Data[1 : 1+newValueLength*2]
				oldValueLength := uint8(tokenEnvChange.Env.Data[1+newValueLength*2])
				oldValue := tokenEnvChange.Env.Data[2+newValueLength*2 : 2+newValueLength*2+oldValueLength*2]

				fmt.Printf("[*] [Env] Change language from %s to %s\n", oldValue, newValue)
			} else if tokenEnvChange.Env.Type == TDS_ENVCHANGE_PACKETSIZE {
				newValueLength := uint8(tokenEnvChange.Env.Data[0])
				newValue := tokenEnvChange.Env.Data[1 : 1+newValueLength*2]
				oldValueLength := uint8(tokenEnvChange.Env.Data[1+newValueLength*2])
				oldValue := tokenEnvChange.Env.Data[2+newValueLength*2 : 2+newValueLength*2+oldValueLength*2]

				fmt.Printf("[*] [Env] Change packet size from %s to %s\n", oldValue, newValue)
			} else if tokenEnvChange.Env.Type == TDS_ENVCHANGE_COLLATION {
				fmt.Printf("[*] [Env] Change collation: %+v\n", tokenEnvChange.Env.Data)
			} else {
				fmt.Printf("[*] [Env] Change env (0x%x): %+v\n", tokenEnvChange.Env.Type, tokenEnvChange.Env.Data)
			}
		case TDS_TOKEN_ERROR:
			tokenInfo := token.(*TdsTokenInfo)
			fmt.Printf("[!] [Error] \"%s\" on server \"%s\" process \"%s\" (lines: %d)\n", tokenInfo.MsgText, tokenInfo.ServerName, tokenInfo.ProcName, tokenInfo.LineNumber)

		case TDS_TOKEN_LOGINACK:
			tokenLoginAck := token.(*TdsTokenLoginAck)
			fmt.Printf("[*] [Login] ACK %s (%d) %d.%d.%d.%d\n", tokenLoginAck.ProgName, tokenLoginAck.TdsVersion, tokenLoginAck.MajorVer, tokenLoginAck.MinorVer, tokenLoginAck.BuildNumberHigh, tokenLoginAck.BuildNumberLow)

		case TDS_TOKEN_RETURNSTATUS:
			tokenReturnValue := token.(*TdsTokenReturnValue)
			fmt.Printf("[*] [Return] status 0x%x\n", tokenReturnValue.Value)

		case TDS_TOKEN_DONE, TDS_TOKEN_DONEINPROC, TDS_TOKEN_DONEPROC:
			tokenDone := token.(*TdsTokenDone)
			tokenId := 0
			fmt.Printf("[*] [Done 0x%x] with status 0x%x cmd 0x%x and %d rows\n", tokenId, tokenDone.Status, tokenDone.CurCmd, tokenDone.DoneRowCount)
		}
	}
}

func (t *TdsTokens) DisplayResults() error {
	colsTokens := t.GetWithType(TDS_TOKEN_COLMETADATA)
	if len(colsTokens) == 0 {
		return nil
	} else if len(colsTokens) > 1 {
		return fmt.Errorf("there more than one (%d) Token Column in the response", len(colsTokens))
	}

	tokenCols := colsTokens[0].(*TdsTokenCols)
	columnName, err := tokenCols.GetColumnNames()
	if err != nil {
		return err
	}

	fmt.Printf(fmt.Sprintf("| %s |\n", strings.Join(columnName, " | ")))

	rowTokens := t.GetWithType(TDS_TOKEN_ROW)
	for _, rowToken := range rowTokens {
		tokenRow := rowToken.(*TdsTokenRow)

		stringValues := make([]string, 0)
		for _, val := range tokenRow.Values {
			stringValues = append(stringValues, fmt.Sprintf("%+v", val))
		}

		fmt.Printf(fmt.Sprintf("| %s |\n", strings.Join(stringValues, " | ")))
	}

	return nil
}

type TdsTokenEnvChangeEnv struct {
	Type uint8
	Data []byte
}

type TdsTokenEnvChange struct {
	TdsTokenWithType
	Length uint16
	Data   []byte
	Env    TdsTokenEnvChangeEnv
}

type TdsTokenInfo struct {
	TdsTokenWithType
	Length           uint16
	Number           uint32
	State            uint8
	Class            uint8
	MsgTextLength    uint16
	MsgText          []byte
	ServerNameLength uint8
	ServerName       []byte
	ProcNameLength   uint8
	ProcName         []byte
	LineNumber       uint16
}

type TdsTokenLoginAck struct {
	TdsTokenWithType
	Length          uint16
	Interface       uint8
	TdsVersion      uint32
	ProgNameLength  uint8
	ProgName        []byte
	MajorVer        uint8
	MinorVer        uint8
	BuildNumberHigh uint8
	BuildNumberLow  uint8
}

type TdsTokenDone struct {
	TdsTokenWithType
	Status       uint16
	CurCmd       uint16
	DoneRowCount uint32
}

type TdsTokenReturnValue struct {
	TdsTokenWithType
	Value uint32
}

type TdsTokenRow struct {
	TdsTokenWithType
	Values []interface{}
}

type TdsTokenCol struct {
	UserType         uint16
	Flags            uint16
	Type             uint8
	TypeData         []byte
	Collation        []byte
	ColumnNameLength uint8
	ColumnName       []byte
}

type TdsTokenCols struct {
	TdsTokenWithType
	Count   uint16
	Columns []*TdsTokenCol
}

func (t *TdsTokenCols) GetColumnNames() ([]string, error) {
	names := make([]string, 0)
	for i, tokenCol := range t.Columns {
		name, err := utils.UTF16DecodeFromBytes(tokenCol.ColumnName)
		if err != nil {
			return nil, fmt.Errorf("cannot utf-16 decode columne name at %d", i)
		}

		names = append(names, name)
	}

	return names, nil
}

func NewTdsTokenEnvChange(tokenType uint8, data []byte) (int, *TdsTokenEnvChange, error) {
	if len(data) < 2 {
		return 0, nil, fmt.Errorf("cannot read TdsTokenEnvChange length")
	}

	length := binary.LittleEndian.Uint16(data)
	if len(data) < 2+int(length) {
		return 0, nil, fmt.Errorf("cannot read TdsTokenEnvChange data")
	}

	tokenEnvChange := &TdsTokenEnvChange{
		TdsTokenWithType: TdsTokenWithType{TokenType: tokenType},
		Length:           length,
		Data:             data[2 : 2+length],
		Env: TdsTokenEnvChangeEnv{
			Type: uint8(data[2]),
			Data: data[3 : 2+length],
		},
	}

	return 2 + int(length), tokenEnvChange, nil
}

func NewTdsTokenInfo(tokenType uint8, data []byte) (int, *TdsTokenInfo, error) {
	if len(data) < 2 {
		return 0, nil, fmt.Errorf("cannot read TdsTokenInfo length")
	}

	length := binary.LittleEndian.Uint16(data)
	if len(data) < 2+int(length) {
		return 0, nil, fmt.Errorf("cannot read TdsTokenInfo data")
	}

	tokenInfo := &TdsTokenInfo{
		TdsTokenWithType: TdsTokenWithType{TokenType: tokenType},
		Length:           length,
	}
	tokenInfo.Number = binary.LittleEndian.Uint32(data[2:])
	tokenInfo.State = uint8(data[6])
	tokenInfo.Class = uint8(data[7])
	tokenInfo.MsgTextLength = binary.LittleEndian.Uint16(data[8:])
	tokenInfo.MsgText = data[10 : 10+tokenInfo.MsgTextLength*2]
	tokenInfo.ServerNameLength = uint8(data[10+tokenInfo.MsgTextLength*2])
	tokenInfo.ServerName = data[11+tokenInfo.MsgTextLength*2 : 11+tokenInfo.MsgTextLength*2+uint16(tokenInfo.ServerNameLength)*2]
	tokenInfo.ProcNameLength = uint8(data[11+tokenInfo.MsgTextLength*2+uint16(tokenInfo.ServerNameLength)*2])
	tokenInfo.ProcName = data[12+tokenInfo.MsgTextLength*2+uint16(tokenInfo.ServerNameLength)*2 : 12+tokenInfo.MsgTextLength*2+uint16(tokenInfo.ServerNameLength)*2+uint16(tokenInfo.ProcNameLength)*2]
	tokenInfo.LineNumber = binary.LittleEndian.Uint16(data[12+tokenInfo.MsgTextLength*2+uint16(tokenInfo.ServerNameLength)*2+uint16(tokenInfo.ProcNameLength)*2:])

	return int(length) + 2, tokenInfo, nil
}

func NewTdsTokenLoginAck(tokenType uint8, data []byte) (int, *TdsTokenLoginAck, error) {
	if len(data) < 2 {
		return 0, nil, fmt.Errorf("cannot read TdsTokenLoginAck length")
	}

	length := binary.LittleEndian.Uint16(data)
	if len(data) < 2+int(length) {
		return 0, nil, fmt.Errorf("cannot read TdsTokenLoginAck data")
	}

	tokenLoginAck := &TdsTokenLoginAck{
		TdsTokenWithType: TdsTokenWithType{TokenType: tokenType},
		Length:           length,
	}
	tokenLoginAck.Interface = uint8(data[2])
	tokenLoginAck.TdsVersion = binary.LittleEndian.Uint32(data[3:])
	tokenLoginAck.ProgNameLength = uint8(data[7])
	tokenLoginAck.ProgName = data[8 : 8+tokenLoginAck.ProgNameLength*2]
	tokenLoginAck.MajorVer = uint8(data[8+tokenLoginAck.ProgNameLength*2])
	tokenLoginAck.MinorVer = uint8(data[9+tokenLoginAck.ProgNameLength*2])
	tokenLoginAck.BuildNumberHigh = uint8(data[10+tokenLoginAck.ProgNameLength*2])
	tokenLoginAck.BuildNumberLow = uint8(data[11+tokenLoginAck.ProgNameLength*2])

	return int(length) + 2, tokenLoginAck, nil
}

func NewTdsTokenDone(tokenType uint8, data []byte) (int, *TdsTokenDone, error) {
	if len(data) < 8 {
		return 0, nil, fmt.Errorf("cannot read TdsTokenDone")
	}

	tokenDone := &TdsTokenDone{
		TdsTokenWithType: TdsTokenWithType{TokenType: tokenType},
		Status:           binary.LittleEndian.Uint16(data[0:]),
		CurCmd:           binary.LittleEndian.Uint16(data[2:]),
		DoneRowCount:     binary.LittleEndian.Uint32(data[4:]),
	}

	return 8, tokenDone, nil
}

func NewTdsTokenReturnValue(tokenType uint8, data []byte) (int, *TdsTokenReturnValue, error) {
	if len(data) < 4 {
		return 0, nil, fmt.Errorf("cannot read TdsTokenReturnValue")
	}

	tokenReturnValue := &TdsTokenReturnValue{
		TdsTokenWithType: TdsTokenWithType{TokenType: tokenType},
		Value:            binary.LittleEndian.Uint32(data[0:]),
	}

	return 4, tokenReturnValue, nil
}

func NewTdsTokenRow(tokenType uint8, data []byte, tokenCols *TdsTokenCols) (int, *TdsTokenRow, error) {
	tokenRow := &TdsTokenRow{
		TdsTokenWithType: TdsTokenWithType{TokenType: tokenType},
		Values:           make([]interface{}, 0),
	}

	n := 0
	for i, tokenCol := range tokenCols.Columns {
		switch tokenCol.Type {
		case TDS_COLUMN_INTNTYPE:
			intSize := uint8(data[n])
			switch intSize {
			case 1:
				tokenRow.Values = append(tokenRow.Values, data[n+1])
			case 2:
				tokenRow.Values = append(tokenRow.Values, binary.LittleEndian.Uint16(data[n+1:]))
			case 4:
				tokenRow.Values = append(tokenRow.Values, binary.LittleEndian.Uint32(data[n+1:]))
			case 8:
				tokenRow.Values = append(tokenRow.Values, binary.LittleEndian.Uint64(data[n+1:]))
			default:
				return 0, nil, fmt.Errorf("invalid int size (%d) at column %d", intSize, i)
			}
			n += 1 + int(intSize)

		case TDS_COLUMN_BITNTYPE:
			length := uint8(data[n])
			tokenRow.Values = append(tokenRow.Values, data[n+1:n+1+int(length)])
			n += 1 + int(length)

		case TDS_COLUMN_NVARCHARTYPE:
			length := binary.LittleEndian.Uint16(data[n:])
			if length == 0xFFFF {
				length = 0
			}

			v, err := utils.UTF16DecodeFromBytes(data[n+2 : n+2+int(length)])
			if err != nil {
				return 0, nil, fmt.Errorf("row has invalid utf16 string at column %d: %s", i, err)
			}
			tokenRow.Values = append(tokenRow.Values, v)
			n += 2 + int(length)

		default:
			return 0, nil, fmt.Errorf("row has unimplemented type 0x%x at column %d", i, tokenCol.Type)
		}
	}

	return n, tokenRow, nil
}

func NewTdsTokenCol(data []byte) (int, *TdsTokenCol, error) {
	if len(data) < 5 {
		return 0, nil, fmt.Errorf("cannot read TdsTokenCol header")
	}

	tokenCol := &TdsTokenCol{}
	tokenCol.UserType = binary.LittleEndian.Uint16(data[0:])
	tokenCol.Flags = binary.LittleEndian.Uint16(data[2:])
	tokenCol.Type = uint8(data[4])

	switch tokenCol.Type {
	case TDS_COLUMN_INTNTYPE, TDS_COLUMN_BITNTYPE:
		tokenCol.TypeData = data[5 : 5+1]
	case TDS_COLUMN_NVARCHARTYPE:
		tokenCol.TypeData = data[5 : 5+2]
	default:
		return 0, nil, fmt.Errorf("unsupported Column Type 0x%x", tokenCol.Type)
	}

	// Collation exceptions
	if tokenCol.Type == TDS_COLUMN_NVARCHARTYPE {
		tokenCol.Collation = data[5+len(tokenCol.TypeData) : 5+len(tokenCol.TypeData)+5]
	}

	tokenCol.ColumnNameLength = uint8(data[5+len(tokenCol.TypeData)+len(tokenCol.Collation)])
	tokenCol.ColumnName = data[6+len(tokenCol.TypeData)+len(tokenCol.Collation) : 6+len(tokenCol.TypeData)+len(tokenCol.Collation)+int(tokenCol.ColumnNameLength)*2]

	return 6 + len(tokenCol.TypeData) + len(tokenCol.Collation) + int(tokenCol.ColumnNameLength)*2, tokenCol, nil
}

func NewTdsTokenCols(tokenType uint8, data []byte) (int, *TdsTokenCols, error) {
	tokenCols := &TdsTokenCols{
		TdsTokenWithType: TdsTokenWithType{TokenType: tokenType},
		Count:            0,
		Columns:          make([]*TdsTokenCol, 0),
	}
	count := binary.LittleEndian.Uint16(data)

	if count == 0xFFFF {
		return 0, tokenCols, nil
	}

	tokenCols.Count = count

	totalN := 2
	for i := uint16(0); i < tokenCols.Count; i++ {
		n, tokenCol, err := NewTdsTokenCol(data[totalN:])
		if err != nil {
			return 0, nil, fmt.Errorf("cannot read Token Col_%d: %s", i, err)
		}
		totalN += n

		tokenCols.Columns = append(tokenCols.Columns, tokenCol)
	}

	return totalN, tokenCols, nil
}
