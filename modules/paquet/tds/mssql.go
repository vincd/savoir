package tds

/*
 * Credits: https://github.com/SecureAuthCorp/impacket/blob/master/impacket/tds.py
 */
import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"

	"golang.org/x/net/proxy"

	"github.com/vincd/savoir/modules/paquet/krb5"
	"github.com/vincd/savoir/modules/paquet/spnego"
	"github.com/vincd/savoir/utils"
)

type MSSQL struct {
	host string
	port uint32

	con    net.Conn
	tlsCon net.Conn

	packetSize uint32
}

func NewMSSQL(host string, port uint32) (*MSSQL, error) {
	return &MSSQL{host: host, port: port, packetSize: 32763}, nil
}

func (m *MSSQL) Connect(dialer proxy.Dialer) error {
	con, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", m.host, m.port))
	if err != nil {
		return fmt.Errorf("cannot dial to %s:%d: %s", m.host, m.port, err)
	}

	m.con = con

	return nil
}

func (m *MSSQL) Close() error {
	if m.con != nil {
		return m.con.Close()
	}

	return nil
}

func (m *MSSQL) sendTDS(packetType uint8, data []byte, packetID uint8) error {
	// TODO: packet with multiple frames
	p := &TdsPacket{
		Type:     packetType,
		Status:   TDS_STATUS_EOM,
		Length:   uint16(8 + len(data)),
		SPID:     0,
		PacketID: packetID,
		Window:   0,
		Data:     data,
	}

	if m.tlsCon == nil {
		if _, err := m.con.Write(p.Bytes()); err != nil {
			return err
		}
	} else {
		if _, err := m.tlsCon.Write(p.Bytes()); err != nil {
			return err
		}
	}

	return nil
}

func (m *MSSQL) recvTDS() (*TdsPacket, error) {
	buf := make([]byte, 32763)
	n, err := m.con.Read(buf)
	if err != nil {
		return nil, err
	}
	buf = buf[:n]

	p, err := NewTdsPacketHeaderWithBytes(buf)
	if err != nil {
		return nil, err
	}

	dataLength := int(p.Length - 8)
	p.Data = buf[8:]

	// Check remaining
	// TODO: handle remaining
	if len(p.Data)+8 > int(p.Length) {
		p.Data = p.Data[:p.Length-8]
	}

	for dataLength > len(p.Data) {
		buf := make([]byte, dataLength-len(p.Data))
		n, err := m.con.Read(buf)
		if err != nil {
			return nil, err
		}
		buf = buf[:n]

		p.Data = append(p.Data, buf...)
	}

	if p.Status == TDS_STATUS_NORMAL {
		nextPacket, err := m.recvTDS()
		if err != nil {
			return nil, fmt.Errorf("cannot recv next TDS packet: %s", err)
		}

		p.Status = nextPacket.Status
		p.Data = append(p.Data, nextPacket.Data...)
		p.Length += nextPacket.Length
	}

	return p, nil
}

func (m *MSSQL) parseReplyTokens(tds *TdsPacket) (*TdsTokens, error) {
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

func (m *MSSQL) recvTdsWithTokens() (*TdsTokens, error) {
	tds, err := m.recvTDS()
	if err != nil {
		return nil, err
	}

	tokens, err := NewTdsTokens(tds)
	if err != nil {
		return nil, err
	}

	tokens.PrintInfos()

	errorTokens := tokens.GetWithType(TDS_TOKEN_ERROR)
	if len(errorTokens) > 1 {
		tokenError := errorTokens[0].(*TdsTokenInfo)
		return nil, fmt.Errorf("an error occured: %s", tokenError.MsgText)
	}

	return tokens, nil
}

func (m *MSSQL) prelogin() (*TdsPrelogin, error) {
	prelogin, err := NewTdsPrelogin([]byte("\x08\x00\x01\x55\x00\x00"), TDS_ENCRYPT_OFF, "MSSQLServer", rand.Uint32())
	if err != nil {
		return nil, err
	}

	if err := m.sendTDS(TDS_PRE_LOGIN, prelogin.Bytes(), 0); err != nil {
		return nil, err
	}

	resp, err := m.recvTDS()
	if err != nil {
		return nil, err
	}

	preloginResp, err := NewTdsPreloginWithBytes(resp.Data)
	if err != nil {
		return nil, err
	}

	return preloginResp, nil
}

func (m *MSSQL) LoginWithKerberos(ticket krb5.Ticket, ticketInfo krb5.KrbCredInfo) error {
	prelogin, err := m.prelogin()
	if err != nil {
		return err
	}

	if prelogin.Encryption[0] == TDS_ENCRYPT_REQ || prelogin.Encryption[0] == TDS_ENCRYPT_OFF {
		fmt.Printf("[*] Encryption required, switching to TLS\n")
		tlsConfig := &tls.Config{
			InsecureSkipVerify:          true,
			DynamicRecordSizingDisabled: true,
		}
		dummyCon := &dummyConn{c: m.con, sendWithTls: true}
		tlsClient := tls.Client(dummyCon, tlsConfig)
		if err = tlsClient.Handshake(); err != nil {
			return fmt.Errorf("error during TDS TLS handshake prelogin: %s", err)
		}

		m.tlsCon = tlsClient
		dummyCon.sendWithTls = false
	}

	serverName, err := utils.UTF16Encode(m.host)
	if err != nil {
		return err
	}

	tdsLogin, err := NewTdsLogin()
	if err != nil {
		return err
	}

	tdsLogin.ClientPID = rand.Uint32() & 0x4ff
	tdsLogin.OptionFlags2 = TDS_INIT_LANG_FATAL | TDS_ODBC_ON
	tdsLogin.PacketSize = m.packetSize // 32763?
	tdsLogin.ServerName = serverName

	auth, err := krb5.NewAuthenticator(ticketInfo.PRealm, ticketInfo.PName)
	if err != nil {
		return err
	}

	encryptedAuthenticator, err := auth.Encrypt(ticketInfo.Key, krb5.KeyUsageApReqAuthenticator)
	if err != nil {
		return err
	}

	apReq, err := krb5.NewAPReq(krb5.NewKerberosFlags(), ticket, *encryptedAuthenticator)
	if err != nil {
		return fmt.Errorf("could create APReq: %s", err)
	}

	negTokenInit, err := spnego.NewNegTokenInit(apReq)
	if err != nil {
		return err
	}

	gssapi, err := spnego.GSSAPI(negTokenInit)
	if err != nil {
		return err
	}

	tdsLogin.OptionFlags2 |= TDS_INTEGRATED_SECURITY_ON
	tdsLogin.SSPI = gssapi
	tdsLogin.Length = uint32(len(tdsLogin.Bytes()))

	m.sendTDS(TDS_LOGIN7, tdsLogin.Bytes(), 1)

	if prelogin.Encryption[0] == TDS_ENCRYPT_OFF {
		m.tlsCon = nil
	}

	tokens, err := m.recvTdsWithTokens()
	if err != nil {
		return err
	}

	if len(tokens.GetWithType(TDS_TOKEN_LOGINACK)) == 0 {
		return fmt.Errorf("server does not send LoginAck token")
	}

	return nil
}

func (m *MSSQL) Batch(cmd string) error {
	fmt.Printf("\nSQL> %s\n", cmd)
	encodedCmd, err := utils.UTF16Encode(fmt.Sprintf("%s\r\n", cmd))
	if err != nil {
		return err
	}

	if err := m.sendTDS(TDS_SQL_BATCH, encodedCmd, 1); err != nil {
		return err
	}

	tokens, err := m.recvTdsWithTokens()
	if err != nil {
		return err
	}

	if err := tokens.DisplayResults(); err != nil {
		return err
	}

	return nil
}
