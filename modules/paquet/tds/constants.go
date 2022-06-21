package tds

const (
	TDS_SQL_BATCH      uint8 = 1
	TDS_PRE_TDS_LOGIN  uint8 = 2
	TDS_RPC            uint8 = 3
	TDS_TABULAR        uint8 = 4
	TDS_ATTENTION      uint8 = 6
	TDS_BULK_LOAD_DATA uint8 = 7
	TDS_TRANSACTION    uint8 = 14
	TDS_LOGIN7         uint8 = 16
	TDS_SSPI           uint8 = 17
	TDS_PRE_LOGIN      uint8 = 18
)

const (
	TDS_STATUS_NORMAL           uint8 = 0
	TDS_STATUS_EOM              uint8 = 1
	TDS_STATUS_RESET_CONNECTION uint8 = 8
	TDS_STATUS_RESET_SKIPTRANS  uint8 = 16
)

const (
	TDS_ENCRYPT_OFF     uint8 = 0
	TDS_ENCRYPT_ON      uint8 = 1
	TDS_ENCRYPT_NOT_SUP uint8 = 2
	TDS_ENCRYPT_REQ     uint8 = 3
)

const (
	TDS_PRELOGIN_TOKEN_VERSION    uint8 = 0
	TDS_PRELOGIN_TOKEN_ENCRYPTION uint8 = 1
	TDS_PRELOGIN_TOKEN_INSTANCE   uint8 = 2
	TDS_PRELOGIN_TOKEN_THREADID   uint8 = 3
	TDS_PRELOGIN_TOKEN_TERMINATOR uint8 = 0xff
)

// Option 2 Flags
const (
	TDS_INTEGRATED_SECURITY_ON uint8 = 0x80
	TDS_INIT_LANG_FATAL        uint8 = 0x01
	TDS_ODBC_ON                uint8 = 0x02
)

const (
	TDS_TOKEN_ALTMETADATA  uint8 = 0x88
	TDS_TOKEN_ALTROW       uint8 = 0xD3
	TDS_TOKEN_COLMETADATA  uint8 = 0x81
	TDS_TOKEN_COLINFO      uint8 = 0xA5
	TDS_TOKEN_DONE         uint8 = 0xFD
	TDS_TOKEN_DONEPROC     uint8 = 0xFE
	TDS_TOKEN_DONEINPROC   uint8 = 0xFF
	TDS_TOKEN_ENVCHANGE    uint8 = 0xE3
	TDS_TOKEN_ERROR        uint8 = 0xAA
	TDS_TOKEN_INFO         uint8 = 0xAB
	TDS_TOKEN_LOGINACK     uint8 = 0xAD
	TDS_TOKEN_NBCROW       uint8 = 0xD2
	TDS_TOKEN_OFFSET       uint8 = 0x78
	TDS_TOKEN_ORDER        uint8 = 0xA9
	TDS_TOKEN_RETURNSTATUS uint8 = 0x79
	TDS_TOKEN_RETURNVALUE  uint8 = 0xAC
	TDS_TOKEN_ROW          uint8 = 0xD1
	TDS_TOKEN_SSPI         uint8 = 0xED
	TDS_TOKEN_TABNAME      uint8 = 0xA4
)

// Column typs
const (
	TDS_COLUMN_INTNTYPE     uint8 = 0x26
	TDS_COLUMN_BITNTYPE     uint8 = 0x68
	TDS_COLUMN_NVARCHARTYPE uint8 = 0xE7
)

// ENVCHANGE Types
const (
	TDS_ENVCHANGE_DATABASE   uint8 = 1
	TDS_ENVCHANGE_LANGUAGE   uint8 = 2
	TDS_ENVCHANGE_PACKETSIZE uint8 = 4
	TDS_ENVCHANGE_COLLATION  uint8 = 7
)
