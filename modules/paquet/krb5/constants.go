package krb5

// Transport information
const (
	KERB_KDC_PORT     = 88
	KERB_KPASSWD_PORT = 464
)

// BER encoding values
const (
	KERB_BER_APPLICATION_TAG  = 0xc0
	KERB_BER_APPLICATION_MASK = 0x1f
)

// https://datatracker.ietf.org/doc/html/rfc4120#section-7.5.2
// https://github.com/cryptoAlgorithm/nt5src/blob/daad8a087a4e75422ec96b7911f1df4669989611/Source/XPSP1/NT/ds/security/protocols/kerberos/inc/kerbcomm.h#L82
const (
	PA_TGS_REQ                 int32 = 1
	PA_ENC_TIMESTAMP           int32 = 2
	PA_PW_SALT                 int32 = 3
	PA_ENC_UNIX_TIME           int32 = 5
	PA_SANDIA_SECUREID         int32 = 6
	PA_SESAME                  int32 = 7
	PA_OSF_DCE                 int32 = 8
	PA_CYBERSAFE_SECUREID      int32 = 9
	PA_AFS3_SALT               int32 = 10
	PA_ETYPE_INFO              int32 = 11
	PA_SAM_CHALLENGE           int32 = 12
	PA_SAM_RESPONSE            int32 = 13
	PA_PK_AS_REQ_OLD           int32 = 14
	PA_PK_AS_REP_OLD           int32 = 15
	PA_PK_AS_REQ               int32 = 16
	PA_PK_AS_REP               int32 = 17
	PA_PK_OCSP_RESPONSE        int32 = 18
	PA_ETYPE_INFO2             int32 = 19
	PA_USE_SPECIFIED_KVNO      int32 = 20
	PA_SVR_REFERRAL_INFO       int32 = 20
	PA_SAM_REDIRECT            int32 = 21
	PA_GET_FROM_TYPED_DATA     int32 = 22
	TD_PADATA                  int32 = 22
	PA_SAM_ETYPE_INFO          int32 = 23
	PA_ALT_PRINC               int32 = 24
	PA_SAM_CHALLENGE2          int32 = 30
	PA_SAM_RESPONSE2           int32 = 31
	PA_EXTRA_TGT               int32 = 41
	TD_PKINIT_CMS_CERTIFICATES int32 = 101
	TD_KRB_PRINCIPAL           int32 = 102
	TD_KRB_REALM               int32 = 103
	TD_TRUSTED_CERTIFIERS      int32 = 104
	TD_CERTIFICATE_INDEX       int32 = 105
	TD_APP_DEFINED_ERROR       int32 = 106
	TD_REQ_NONCE               int32 = 107
	TD_REQ_SEQ                 int32 = 108
	PA_PAC_REQUEST             int32 = 128
)

// https://datatracker.ietf.org/doc/html/rfc4120#section-7.5.6
const (
	PVNO = 5 // Current Kerberos protocol version number
)

// https://datatracker.ietf.org/doc/html/rfc4120#section-7.5.7
// https://github.com/cryptoAlgorithm/nt5src/blob/daad8a087a4e75422ec96b7911f1df4669989611/Source/XPSP1/NT/ds/security/protocols/kerberos/inc/kerbcomm.h#L63
const (
	KRB_AS_REQ     = 10 // Request for initial authentication
	KRB_AS_REP     = 11 // Response to KRB_AS_REQ request
	KRB_TGS_REQ    = 12 // Request for authentication based on TGT
	KRB_TGS_REP    = 13 // Response to KRB_TGS_REQ request
	KRB_AP_REQ     = 14 // Application request to server
	KRB_AP_REP     = 15 // Response to KRB_AP_REQ_MUTUAL
	KRB_RESERVED16 = 16 // Reserved for user-to-user krb_tgt_request
	KRB_RESERVED17 = 17 // Reserved for user-to-user krb_tgt_reply
	KRB_SAFE       = 20 // Safe (checksummed) application message
	KRB_PRIV       = 21 // Private (encrypted) application message
	KRB_CRED       = 22 // Private (encrypted) message to forward credentials
	KRB_ERROR      = 30 // Error response
)

// https://datatracker.ietf.org/doc/html/rfc4120#section-7.5.8
const (
	KRB_NT_UNKNOWN              int32 = 0  // Name type not known
	KRB_NT_PRINCIPAL            int32 = 1  // Just the name of the principal as in DCE,  or for users
	KRB_NT_SRV_INST             int32 = 2  // Service and other unique instance (krbtgt)
	KRB_NT_SRV_HST              int32 = 3  // Service with host name as instance (telnet, rcommands)
	KRB_NT_SRV_XHST             int32 = 4  // Service with host as remaining components
	KRB_NT_UID                  int32 = 5  // Unique ID
	KRB_NT_X500_PRINCIPAL       int32 = 6  // Encoded X.509 Distinguished name [RFC2253]
	KRB_NT_SMTP_NAME            int32 = 7  // Name in form of SMTP email name (e.g., user@example.com)
	KRB_NT_ENTERPRISE           int32 = 10 // Enterprise name; may be mapped to principal name
	KRB_NT_MS_PRINCIPAL         int32 = -128
	KRB_NT_MS_PRINCIPAL_AND_ID  int32 = -129
	KRB_NT_ENT_PRINCIPAL_AND_ID int32 = -130
)

// https://datatracker.ietf.org/doc/html/rfc4120#section-7.5.9
const (
	KDC_ERR_NONE                          int32 = 0  // No error
	KDC_ERR_NAME_EXP                      int32 = 1  // Client's entry in database has expired
	KDC_ERR_SERVICE_EXP                   int32 = 2  // Server's entry in database has expired
	KDC_ERR_BAD_PVNO                      int32 = 3  // Requested protocol version number not supported
	KDC_ERR_C_OLD_MAST_KVNO               int32 = 4  // Client's key encrypted in old master key
	KDC_ERR_S_OLD_MAST_KVNO               int32 = 5  // Server's key encrypted in old master key
	KDC_ERR_C_PRINCIPAL_UNKNOWN           int32 = 6  // Client not found in Kerberos database
	KDC_ERR_S_PRINCIPAL_UNKNOWN           int32 = 7  // Server not found in Kerberos database
	KDC_ERR_PRINCIPAL_NOT_UNIQUE          int32 = 8  // Multiple principal entries in database
	KDC_ERR_NULL_KEY                      int32 = 9  // The client or server has a null key
	KDC_ERR_CANNOT_POSTDATE               int32 = 10 // Ticket not eligible for postdating
	KDC_ERR_NEVER_VALID                   int32 = 11 // Requested starttime is later than end time
	KDC_ERR_POLICY                        int32 = 12 // KDC policy rejects request
	KDC_ERR_BADOPTION                     int32 = 13 // KDC cannot accommodate requested option
	KDC_ERR_ETYPE_NOSUPP                  int32 = 14 // KDC has no support for encryption type
	KDC_ERR_SUMTYPE_NOSUPP                int32 = 15 // KDC has no support for checksum type
	KDC_ERR_PADATA_TYPE_NOSUPP            int32 = 16 // KDC has no support for padata type
	KDC_ERR_TRTYPE_NOSUPP                 int32 = 17 // KDC has no support for transited type
	KDC_ERR_CLIENT_REVOKED                int32 = 18 // Clients credentials have been revoked
	KDC_ERR_SERVICE_REVOKED               int32 = 19 // Credentials for server have been revoked
	KDC_ERR_TGT_REVOKED                   int32 = 20 // TGT has been revoked
	KDC_ERR_CLIENT_NOTYET                 int32 = 21 // Client not yet valid; try again later
	KDC_ERR_SERVICE_NOTYET                int32 = 22 // Server not yet valid; try again later
	KDC_ERR_KEY_EXPIRED                   int32 = 23 // Password has expired; change password to reset
	KDC_ERR_PREAUTH_FAILED                int32 = 24 // Pre-authentication information was invalid
	KDC_ERR_PREAUTH_REQUIRED              int32 = 25 // Additional pre-authentication required
	KDC_ERR_SERVER_NOMATCH                int32 = 26 // Requested server and ticket don't match
	KDC_ERR_MUST_USE_USER2USER            int32 = 27 // Server principal valid for user2user only
	KDC_ERR_PATH_NOT_ACCEPTED             int32 = 28 // KDC Policy rejects transited path
	KDC_ERR_SVC_UNAVAILABLE               int32 = 29 // A service is not available
	KRB_AP_ERR_BAD_INTEGRITY              int32 = 31 // Integrity check on decrypted field failed
	KRB_AP_ERR_TKT_EXPIRED                int32 = 32 // Ticket expired
	KRB_AP_ERR_TKT_NYV                    int32 = 33 // Ticket not yet valid
	KRB_AP_ERR_REPEAT                     int32 = 34 // Request is a replay
	KRB_AP_ERR_NOT_US                     int32 = 35 // The ticket isn't for us
	KRB_AP_ERR_BADMATCH                   int32 = 36 // Ticket and authenticator don't match
	KRB_AP_ERR_SKEW                       int32 = 37 // Clock skew too great
	KRB_AP_ERR_BADADDR                    int32 = 38 // Incorrect net address
	KRB_AP_ERR_BADVERSION                 int32 = 39 // Protocol version mismatch
	KRB_AP_ERR_MSG_TYPE                   int32 = 40 // Invalid msg type
	KRB_AP_ERR_MODIFIED                   int32 = 41 // Message stream modified
	KRB_AP_ERR_BADORDER                   int32 = 42 // Message out of order
	KRB_AP_ERR_BADKEYVER                  int32 = 44 // Specified version of key is not available
	KRB_AP_ERR_NOKEY                      int32 = 45 // Service key not available
	KRB_AP_ERR_MUT_FAIL                   int32 = 46 // Mutual authentication failed
	KRB_AP_ERR_BADDIRECTION               int32 = 47 // Incorrect message direction
	KRB_AP_ERR_METHOD                     int32 = 48 // Alternative authentication method required
	KRB_AP_ERR_BADSEQ                     int32 = 49 // Incorrect sequence number in message
	KRB_AP_ERR_INAPP_CKSUM                int32 = 50 // Inappropriate type of checksum in message
	KRB_AP_PATH_NOT_ACCEPTED              int32 = 51 // Policy rejects transited path
	KRB_ERR_RESPONSE_TOO_BIG              int32 = 52 // Response too big for UDP;  retry with TCP
	KRB_ERR_GENERIC                       int32 = 60 // Generic error (description in e-text)
	KRB_ERR_FIELD_TOOLONG                 int32 = 61 // Field is too long for this implementation
	KDC_ERROR_CLIENT_NOT_TRUSTED          int32 = 62 // Reserved for PKINIT
	KDC_ERROR_KDC_NOT_TRUSTED             int32 = 63 // Reserved for PKINIT
	KDC_ERROR_INVALID_SIG                 int32 = 64 // Reserved for PKINIT
	KDC_ERR_KEY_TOO_WEAK                  int32 = 65 // Reserved for PKINIT
	KDC_ERR_CERTIFICATE_MISMATCH          int32 = 66 // Reserved for PKINIT
	KRB_AP_ERR_NO_TGT                     int32 = 67 // No TGT available to validate USER-TO-USER
	KDC_ERR_WRONG_REALM                   int32 = 68 // Reserved for future use
	KRB_AP_ERR_USER_TO_USER_REQUIRED      int32 = 69 // Ticket must be for USER-TO-USER
	KDC_ERR_CANT_VERIFY_CERTIFICATE       int32 = 70 // Reserved for PKINIT
	KDC_ERR_INVALID_CERTIFICATE           int32 = 71 // Reserved for PKINIT
	KDC_ERR_REVOKED_CERTIFICATE           int32 = 72 // Reserved for PKINIT
	KDC_ERR_REVOCATION_STATUS_UNKNOWN     int32 = 73 // Reserved for PKINIT
	KDC_ERR_REVOCATION_STATUS_UNAVAILABLE int32 = 74 // Reserved for PKINIT
	KDC_ERR_CLIENT_NAME_MISMATCH          int32 = 75 // Reserved for PKINIT
	KDC_ERR_KDC_NAME_MISMATCH             int32 = 76 // Reserved for PKINIT
)

var errorcodeById = map[int32]string{
	KDC_ERR_NONE:                          "KDC_ERR_NONE No error",
	KDC_ERR_NAME_EXP:                      "KDC_ERR_NAME_EXP Client's entry in database has expired",
	KDC_ERR_SERVICE_EXP:                   "KDC_ERR_SERVICE_EXP Server's entry in database has expired",
	KDC_ERR_BAD_PVNO:                      "KDC_ERR_BAD_PVNO Requested protocol version number not supported",
	KDC_ERR_C_OLD_MAST_KVNO:               "KDC_ERR_C_OLD_MAST_KVNO Client's key encrypted in old master key",
	KDC_ERR_S_OLD_MAST_KVNO:               "KDC_ERR_S_OLD_MAST_KVNO Server's key encrypted in old master key",
	KDC_ERR_C_PRINCIPAL_UNKNOWN:           "KDC_ERR_C_PRINCIPAL_UNKNOWN Client not found in Kerberos database",
	KDC_ERR_S_PRINCIPAL_UNKNOWN:           "KDC_ERR_S_PRINCIPAL_UNKNOWN Server not found in Kerberos database",
	KDC_ERR_PRINCIPAL_NOT_UNIQUE:          "KDC_ERR_PRINCIPAL_NOT_UNIQUE Multiple principal entries in database",
	KDC_ERR_NULL_KEY:                      "KDC_ERR_NULL_KEY The client or server has a null key",
	KDC_ERR_CANNOT_POSTDATE:               "KDC_ERR_CANNOT_POSTDATE Ticket not eligible for postdating",
	KDC_ERR_NEVER_VALID:                   "KDC_ERR_NEVER_VALID Requested starttime is later than end time",
	KDC_ERR_POLICY:                        "KDC_ERR_POLICY KDC policy rejects request",
	KDC_ERR_BADOPTION:                     "KDC_ERR_BADOPTION KDC cannot accommodate requested option",
	KDC_ERR_ETYPE_NOSUPP:                  "KDC_ERR_ETYPE_NOSUPP KDC has no support for encryption type",
	KDC_ERR_SUMTYPE_NOSUPP:                "KDC_ERR_SUMTYPE_NOSUPP KDC has no support for checksum type",
	KDC_ERR_PADATA_TYPE_NOSUPP:            "KDC_ERR_PADATA_TYPE_NOSUPP KDC has no support for padata type",
	KDC_ERR_TRTYPE_NOSUPP:                 "KDC_ERR_TRTYPE_NOSUPP KDC has no support for transited type",
	KDC_ERR_CLIENT_REVOKED:                "KDC_ERR_CLIENT_REVOKED Clients credentials have been revoked",
	KDC_ERR_SERVICE_REVOKED:               "KDC_ERR_SERVICE_REVOKED Credentials for server have been revoked",
	KDC_ERR_TGT_REVOKED:                   "KDC_ERR_TGT_REVOKED TGT has been revoked",
	KDC_ERR_CLIENT_NOTYET:                 "KDC_ERR_CLIENT_NOTYET Client not yet valid; try again later",
	KDC_ERR_SERVICE_NOTYET:                "KDC_ERR_SERVICE_NOTYET Server not yet valid; try again later",
	KDC_ERR_KEY_EXPIRED:                   "KDC_ERR_KEY_EXPIRED Password has expired; change password to reset",
	KDC_ERR_PREAUTH_FAILED:                "KDC_ERR_PREAUTH_FAILED Pre-authentication information was invalid",
	KDC_ERR_PREAUTH_REQUIRED:              "KDC_ERR_PREAUTH_REQUIRED Additional pre-authentication required",
	KDC_ERR_SERVER_NOMATCH:                "KDC_ERR_SERVER_NOMATCH Requested server and ticket don't match",
	KDC_ERR_MUST_USE_USER2USER:            "KDC_ERR_MUST_USE_USER2USER Server principal valid for  user2user only",
	KDC_ERR_PATH_NOT_ACCEPTED:             "KDC_ERR_PATH_NOT_ACCEPTED KDC Policy rejects transited path",
	KDC_ERR_SVC_UNAVAILABLE:               "KDC_ERR_SVC_UNAVAILABLE A service is not available",
	KRB_AP_ERR_BAD_INTEGRITY:              "KRB_AP_ERR_BAD_INTEGRITY Integrity check on decrypted field failed",
	KRB_AP_ERR_TKT_EXPIRED:                "KRB_AP_ERR_TKT_EXPIRED Ticket expired",
	KRB_AP_ERR_TKT_NYV:                    "KRB_AP_ERR_TKT_NYV Ticket not yet valid",
	KRB_AP_ERR_REPEAT:                     "KRB_AP_ERR_REPEAT Request is a replay",
	KRB_AP_ERR_NOT_US:                     "KRB_AP_ERR_NOT_US The ticket isn't for us",
	KRB_AP_ERR_BADMATCH:                   "KRB_AP_ERR_BADMATCH Ticket and authenticator don't match",
	KRB_AP_ERR_SKEW:                       "KRB_AP_ERR_SKEW Clock skew too great",
	KRB_AP_ERR_BADADDR:                    "KRB_AP_ERR_BADADDR Incorrect net address",
	KRB_AP_ERR_BADVERSION:                 "KRB_AP_ERR_BADVERSION Protocol version mismatch",
	KRB_AP_ERR_MSG_TYPE:                   "KRB_AP_ERR_MSG_TYPE Invalid msg type",
	KRB_AP_ERR_MODIFIED:                   "KRB_AP_ERR_MODIFIED Message stream modified",
	KRB_AP_ERR_BADORDER:                   "KRB_AP_ERR_BADORDER Message out of order",
	KRB_AP_ERR_BADKEYVER:                  "KRB_AP_ERR_BADKEYVER Specified version of key is not available",
	KRB_AP_ERR_NOKEY:                      "KRB_AP_ERR_NOKEY Service key not available",
	KRB_AP_ERR_MUT_FAIL:                   "KRB_AP_ERR_MUT_FAIL Mutual authentication failed",
	KRB_AP_ERR_BADDIRECTION:               "KRB_AP_ERR_BADDIRECTION Incorrect message direction",
	KRB_AP_ERR_METHOD:                     "KRB_AP_ERR_METHOD Alternative authentication method required",
	KRB_AP_ERR_BADSEQ:                     "KRB_AP_ERR_BADSEQ Incorrect sequence number in message",
	KRB_AP_ERR_INAPP_CKSUM:                "KRB_AP_ERR_INAPP_CKSUM Inappropriate type of checksum in message",
	KRB_AP_PATH_NOT_ACCEPTED:              "KRB_AP_PATH_NOT_ACCEPTED Policy rejects transited path",
	KRB_ERR_RESPONSE_TOO_BIG:              "KRB_ERR_RESPONSE_TOO_BIG Response too big for UDP; retry with TCP",
	KRB_ERR_GENERIC:                       "KRB_ERR_GENERIC Generic error (description in e-text)",
	KRB_ERR_FIELD_TOOLONG:                 "KRB_ERR_FIELD_TOOLONG Field is too long for this implementation",
	KDC_ERROR_CLIENT_NOT_TRUSTED:          "KDC_ERROR_CLIENT_NOT_TRUSTED Reserved for PKINIT",
	KDC_ERROR_KDC_NOT_TRUSTED:             "KDC_ERROR_KDC_NOT_TRUSTED Reserved for PKINIT",
	KDC_ERROR_INVALID_SIG:                 "KDC_ERROR_INVALID_SIG Reserved for PKINIT",
	KDC_ERR_KEY_TOO_WEAK:                  "KDC_ERR_KEY_TOO_WEAK Reserved for PKINIT",
	KDC_ERR_CERTIFICATE_MISMATCH:          "KDC_ERR_CERTIFICATE_MISMATCH Reserved for PKINIT",
	KRB_AP_ERR_NO_TGT:                     "KRB_AP_ERR_NO_TGT No TGT available to validate USER-TO-USER",
	KDC_ERR_WRONG_REALM:                   "KDC_ERR_WRONG_REALM Reserved for future use",
	KRB_AP_ERR_USER_TO_USER_REQUIRED:      "KRB_AP_ERR_USER_TO_USER_REQUIRED Ticket must be for USER-TO-USER",
	KDC_ERR_CANT_VERIFY_CERTIFICATE:       "KDC_ERR_CANT_VERIFY_CERTIFICATE Reserved for PKINIT",
	KDC_ERR_INVALID_CERTIFICATE:           "KDC_ERR_INVALID_CERTIFICATE Reserved for PKINIT",
	KDC_ERR_REVOKED_CERTIFICATE:           "KDC_ERR_REVOKED_CERTIFICATE Reserved for PKINIT",
	KDC_ERR_REVOCATION_STATUS_UNKNOWN:     "KDC_ERR_REVOCATION_STATUS_UNKNOWN Reserved for PKINIT",
	KDC_ERR_REVOCATION_STATUS_UNAVAILABLE: "KDC_ERR_REVOCATION_STATUS_UNAVAILABLE Reserved for PKINIT",
	KDC_ERR_CLIENT_NAME_MISMATCH:          "KDC_ERR_CLIENT_NAME_MISMATCH Reserved for PKINIT",
	KDC_ERR_KDC_NAME_MISMATCH:             "KDC_ERR_KDC_NAME_MISMATCH Reserved for PKINIT",
}
