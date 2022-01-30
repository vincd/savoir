package krb5

import (
	"fmt"

	"github.com/vincd/savoir/modules/paquet/krb5/crypto"
	"github.com/vincd/savoir/utils/asn1"
)

func ensureResponseTag(res []byte, expectedTag byte) error {
	resTag := getStructureTag(res)

	if expectedTag != TagKRBError && resTag == TagKRBError {
		kError := &KRBError{}
		if err := kError.Unmarshal(res); err != nil {
			return err
		}

		return kError.Error()
	}

	// Ensure we have the correct response
	if resTag != expectedTag {
		return fmt.Errorf("KGC responds with the tag %d instead of %d.", resTag, expectedTag)
	}

	return nil
}

// AskTGT:
//  * noPreauth: return TGT (with undecrypted tickets) if true
//  * noPac: as no-pac to the KDC (not tested)
func AskTGT(domain string, username string, password string, key []byte, eTypeValue int32, dcIp string, noPreauth bool, noPac bool) (*ASRep, error) {
	if len(domain) == 0 {
		return nil, fmt.Errorf("Domain name cannot be empty")
	}

	eType, err := crypto.NewEType(eTypeValue)
	if err != nil {
		return nil, err
	}

	clientName := PrincipalName{
		NameType:   KRB_NT_PRINCIPAL,
		NameString: []string{username},
	}
	serverName := PrincipalName{
		NameType:   KRB_NT_PRINCIPAL, // KRB_NT_SRV_INST ?
		NameString: []string{"krbtgt", domain},
	}
	// TODO: KDCOptions depends on how we want to ask the ticket
	kOptions := NewKDCOptions()
	SetKerberosFlag(&kOptions, KDCFlagsProxiable)

	req, err := NewASReq(domain, clientName, serverName, kOptions, eType.GetEtype())
	if err != nil {
		return nil, err
	}

	// Add PAC
	kerbpacRequest, err := NewKerbPaPacRequest(!noPac)
	if err != nil {
		return nil, err
	}
	req.PAData = []PAData{*kerbpacRequest}

	if len(key) == 0 {
		// Send request to KDC
		res, err := SendMessage(dcIp, req)
		if err != nil {
			return nil, err
		}

		// Get the response type to check the preauthentication
		resType := getStructureTag(res)

		// There is no preauthentication: `Do not require Kerberos preauthentication`
		if resType == TagASREP && noPreauth {
			// The response is a valid TGT
			asRep := &ASRep{}
			if err := asRep.Unmarshal(res); err != nil {
				return nil, fmt.Errorf("Cannot unmarshall ASRep with no pre-authentication: %s", err)
			}

			return asRep, nil
		}

		// Parse the PAData to get information about key generation
		paDatas := make([]PAData, 0)

		if resType == TagASREP {
			if resType != TagASREP {
				return nil, fmt.Errorf("Unauthenticated AS-Req with no-preauthentication should return AS-Rep, it returns the type %d instead", resType)
			}

			noPreauthTGT := &ASRep{}
			if err := noPreauthTGT.Unmarshal(res); err != nil {
				return nil, fmt.Errorf("Cannot unmarshall ASRep: %s", err)
			}

			// The TGT should conatains the informations we need (for AES)
			paDatas = noPreauthTGT.PAData
		} else {
			// Ensure with have an error because we need a preauthentication
			if resType != KRB_ERROR {
				return nil, fmt.Errorf("Unauthenticated AS-Req should return an error, it returns the type %d instead", resType)
			}

			kError := &KRBError{}
			if err := kError.Unmarshal(res); err != nil {
				return nil, err
			}

			if kError.ErrorCode == KDC_ERR_ETYPE_NOSUPP {
				return nil, fmt.Errorf("[KDC_ERR_ETYPE_NOSUPP] KDC has no support for encryption type %s", eType)
			} else if kError.ErrorCode == KDC_ERR_C_PRINCIPAL_UNKNOWN {
				return nil, fmt.Errorf("[KDC_ERR_C_PRINCIPAL_UNKNOWN] KDC does not know client with principal \"%s\"", username)
			} else if kError.ErrorCode != KDC_ERR_PREAUTH_REQUIRED {
				return nil, fmt.Errorf("Unauthenticated ASRep returns the error: %s", kError.String())
			}

			if _, err := asn1.Unmarshal(kError.EData, &paDatas); err != nil {
				return nil, err
			}
		}

		salt := ""
		s2kp := ""
		for _, pa := range paDatas {
			switch pa.PADataType {
			case PA_ETYPE_INFO:
				et := make([]EtypeInfoEntry, 0)
				if _, err := asn1.Unmarshal(pa.PADataValue, &et); err != nil {
					return nil, fmt.Errorf("Cannot unmarshal PA_ETYPE_INFO from PAData: %s", err)
				}

				if len(et) != 1 {
					return nil, fmt.Errorf("PAData contains a PA_ETYPE_INFO sequence with len=%d", len(et))
				}

				salt = et[0].Salt

			case PA_ETYPE_INFO2:
				et2 := make([]EtypeInfo2Entry, 0)
				if _, err := asn1.Unmarshal(pa.PADataValue, &et2); err != nil {
					return nil, fmt.Errorf("Cannot unmarshal PA_ETYPE_INFO2 from PAData: %s", err)
				}

				if len(et2) != 1 {
					return nil, fmt.Errorf("PAData contains a PA_ETYPE_INFO2 sequence with len=%d", len(et2))
				}

				salt = et2[0].Salt
				if len(et2[0].S2KParams) == 4 {
					s2kp = string(et2[0].S2KParams)
				}

				if et2[0].EType != eType.GetEtype() {
					eType, err = crypto.NewEType(et2[0].EType)
					if err != nil {
						return nil, err
					}
				}
			}
		}

		// Generate encryption key
		key, err = eType.GenerateSecretkey(password, salt, s2kp)
		if err != nil {
			return nil, err
		}
	}

	paEncTsEnc, err := NewPADataEncrypted(PA_ENC_TIMESTAMP, NewPAEncTsEnc(), eType.GetEtype(), key)
	if err != nil {
		return nil, err
	}
	req.PAData = append(req.PAData, *paEncTsEnc)

	// Send ASReq with encrypted timestamp
	asRepBytes, err := SendMessage(dcIp, req)
	if err != nil {
		return nil, err
	}

	if err := ensureResponseTag(asRepBytes, TagASREP); err != nil {
		return nil, fmt.Errorf("Authenticated ASRep returns an invalid structure: %s", err)
	}

	tgt := &ASRep{}
	if err := tgt.Unmarshal(asRepBytes); err != nil {
		return nil, fmt.Errorf("Cannot unmarshall ASRep: %s", err)
	}

	// Decrypt session key
	if err := tgt.DecryptAsRepPart(key); err != nil {
		return nil, err
	}

	return tgt, nil
}

func AskTGS(domain string, serverName PrincipalName, clientRealm string, ClientName PrincipalName, ticket Ticket, key EncryptionKey, dcIp string) (*TGSRep, error) {
	auth, err := NewAuthenticator(clientRealm, ClientName)
	if err != nil {
		return nil, err
	}

	// The DER encoding of the following is
	// encrypted in the ticket's session key, with a key usage value of 11
	// in normal application exchanges, or 7 when used as the PA-TGS-REQ
	// PA-DATA field of a TGS-REQ exchange (see Section 5.4.1):
	encryptedAuthenticator, err := auth.Encrypt(key, 7)
	if err != nil {
		return nil, err
	}

	apReq, err := NewAPReq(NewKerberosFlags(), ticket, *encryptedAuthenticator)
	if err != nil {
		return nil, fmt.Errorf("Cannot generate APReq: %s", err)
	}

	// TODO: KDCOptions depends on how we want to ask the ticket
	kOptions := NewKDCOptions()
	SetKerberosFlag(&kOptions, KDCFlagsCanonicalize)

	encTypes := []int32{key.KeyType}
	tgsReq, err := NewTGSReq(apReq, domain, PrincipalName{}, serverName, kOptions, encTypes)
	if err != nil {
		return nil, fmt.Errorf("Cannot generate TGSReq: %s", err)
	}

	res, err := SendMessage(dcIp, tgsReq)
	if err != nil {
		return nil, err
	}

	if err := ensureResponseTag(res, TagTGSREP); err != nil {
		return nil, fmt.Errorf("TGSReq returns an invalid structure: %s.", err)
	}

	tgs := &TGSRep{}
	if err := tgs.Unmarshal(res); err != nil {
		return nil, fmt.Errorf("Cannot unmarshall TGSRep: %s.", err)
	}

	// Decrypt new session key
	if err := tgs.DecryptTgsRepPart(key.KeyValue); err != nil {
		return nil, err
	}

	// Check if the KDC supplies the correct SPN
	if tgs.Ticket.SName.NameString[0] != serverName.NameString[0] {
		return nil, fmt.Errorf("KDC does not return the correct ServerName, it returns: %s.", tgs.Ticket.SName.NameString)
	}

	return tgs, nil
}

func AskTGSWithTGT(domain string, serverName PrincipalName, tgt *ASRep, dcIp string) (*TGSRep, error) {
	return AskTGS(domain, serverName, tgt.CRealm, tgt.CName, tgt.KDCRep.Ticket, tgt.DecryptedEncPart.Key, dcIp)
}

func AskTGSWithKirbi(domain string, serverName PrincipalName, kirbi *KRBCred, dcIp string) (*TGSRep, error) {
	if len(kirbi.DecryptedEncPart.TicketInfo) == 0 {
		return nil, fmt.Errorf("Kirbi file does not have TicketInfo field.")
	}

	if len(kirbi.Tickets) == 0 {
		return nil, fmt.Errorf("Kirbi file does not have any ticket.")
	}

	info := kirbi.DecryptedEncPart.TicketInfo[0]
	ticket := kirbi.Tickets[0]

	return AskTGS(domain, serverName, info.PRealm, info.PName, ticket, info.Key, dcIp)
}
