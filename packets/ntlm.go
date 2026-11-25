package packets

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
)

const (
	ntlmSignature = "NTLMSSP\x00"

	NTLM_SIG_OFFSET  = 0
	NTLM_TYPE_OFFSET = 8

	NTLM_TYPE1_FLAGS_OFFSET   = 12
	NTLM_TYPE1_DOMAIN_OFFSET  = 16
	NTLM_TYPE1_WORKSTN_OFFSET = 24
	NTLM_TYPE1_DATA_OFFSET    = 32
	NTLM_TYPE1_MINSIZE        = 16

	NTLM_TYPE2_TARGET_OFFSET     = 12
	NTLM_TYPE2_FLAGS_OFFSET      = 20
	NTLM_TYPE2_CHALLENGE_OFFSET  = 24
	NTLM_TYPE2_CONTEXT_OFFSET    = 32
	NTLM_TYPE2_TARGETINFO_OFFSET = 40
	NTLM_TYPE2_DATA_OFFSET       = 48
	NTLM_TYPE2_MINSIZE           = 32

	NTLM_TYPE3_LMRESP_OFFSET     = 12
	NTLM_TYPE3_NTRESP_OFFSET     = 20
	NTLM_TYPE3_DOMAIN_OFFSET     = 28
	NTLM_TYPE3_USER_OFFSET       = 36
	NTLM_TYPE3_WORKSTN_OFFSET    = 44
	NTLM_TYPE3_SESSIONKEY_OFFSET = 52
	NTLM_TYPE3_FLAGS_OFFSET      = 60
	NTLM_TYPE3_DATA_OFFSET       = 64
	NTLM_TYPE3_MINSIZE           = 52

	NTLM_BUFFER_LEN_OFFSET    = 0
	NTLM_BUFFER_MAXLEN_OFFSET = 2
	NTLM_BUFFER_OFFSET_OFFSET = 4
	NTLM_BUFFER_SIZE          = 8

	NtlmV1 = 1
	NtlmV2 = 2
)

type NTLMChallengeResponse struct {
	Challenge string
	Response  string
}

type NTLMChallengeResponseParsed struct {
	Type            int
	ServerChallenge string
	User            string
	Domain          string
	LmHash          string
	NtHashOne       string
	NtHashTwo       string
}

type NTLMResponseHeader struct {
	Sig          string
	Type         uint32
	LmLen        uint16
	LmMax        uint16
	LmOffset     uint16
	NtLen        uint16
	NtMax        uint16
	NtOffset     uint16
	DomainLen    uint16
	DomainMax    uint16
	DomainOffset uint16
	UserLen      uint16
	UserMax      uint16
	UserOffset   uint16
	HostLen      uint16
	HostMax      uint16
	HostOffset   uint16
}

type NTLMState struct {
	sync.Mutex

	Responses map[uint32]string
	Pairs     []NTLMChallengeResponse
}

func (s *NTLMState) AddServerResponse(key uint32, value string) {
	s.Lock()
	defer s.Unlock()
	s.Responses[key] = value
}

func (s *NTLMState) AddClientResponse(seq uint32, value string, cb func(data NTLMChallengeResponseParsed)) {
	s.Lock()
	defer s.Unlock()

	chall, found := s.Responses[seq]
	if !found {
		return
	}

	pair := NTLMChallengeResponse{
		Challenge: chall,
		Response:  value,
	}

	// Validate before publishing the pair. Appending only after Parsed
	// succeeds ensures malformed or anonymous NTLM material cannot enter
	// the replay/evidence state. A failed validation leaves existing pairs
	// untouched.
	data, err := pair.Parsed()
	if err != nil {
		return
	}

	s.Pairs = append(s.Pairs, pair)
	if cb != nil {
		cb(data)
	}
}

func NewNTLMState() *NTLMState {
	return &NTLMState{
		Responses: make(map[uint32]string),
		Pairs:     make([]NTLMChallengeResponse, 0),
	}
}

var (
	ErrInvalidNTLMChallenge   = errors.New("invalid NTLM challenge")
	ErrInvalidNTLMResponse    = errors.New("invalid NTLM response")
	ErrIncompleteNTLMIdentity = errors.New("incomplete NTLM identity")
)

func (sr NTLMChallengeResponse) decodeChallenge() ([]byte, error) {
	dataChallenge, err := base64.StdEncoding.DecodeString(sr.Challenge)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed base64: %v", ErrInvalidNTLMChallenge, err)
	}
	if len(dataChallenge) < NTLM_TYPE2_CHALLENGE_OFFSET+8 {
		return nil, fmt.Errorf("%w: message is too short", ErrInvalidNTLMChallenge)
	}
	if string(dataChallenge[:len(ntlmSignature)]) != ntlmSignature {
		return nil, fmt.Errorf("%w: bad signature", ErrInvalidNTLMChallenge)
	}
	if messageType := binary.LittleEndian.Uint32(dataChallenge[NTLM_TYPE_OFFSET : NTLM_TYPE_OFFSET+4]); messageType != 2 {
		return nil, fmt.Errorf("%w: unexpected message type %d", ErrInvalidNTLMChallenge, messageType)
	}
	return dataChallenge, nil
}

func (sr NTLMChallengeResponse) getChallengeBytes() []byte {
	dataChallenge, _ := sr.decodeChallenge()
	return dataChallenge
}

func (sr NTLMChallengeResponse) getServerChallenge() string {
	challenge, _ := sr.serverChallenge()
	return challenge
}

func (sr NTLMChallengeResponse) serverChallenge() (string, error) {
	dataChallenge, err := sr.decodeChallenge()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(dataChallenge[NTLM_TYPE2_CHALLENGE_OFFSET : NTLM_TYPE2_CHALLENGE_OFFSET+8]), nil
}

func (sr NTLMChallengeResponse) getResponseBytes() []byte {
	dataResponse, _ := base64.StdEncoding.DecodeString(sr.Response)
	return dataResponse
}

func (sr NTLMChallengeResponse) decodeResponse() ([]byte, error) {
	dataResponse, err := base64.StdEncoding.DecodeString(sr.Response)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed base64: %v", ErrInvalidNTLMResponse, err)
	}
	return dataResponse, nil
}
func (sr *NTLMChallengeResponse) Parsed() (NTLMChallengeResponseParsed, error) {
	if sr.isNtlmV1() {
		return sr.ParsedNtLMv1()
	}
	return sr.ParsedNtLMv2()
}

func (sr *NTLMChallengeResponse) ParsedNtLMv2() (NTLMChallengeResponseParsed, error) {
	r, b, err := sr.parsedResponseHeader()
	if err != nil {
		return NTLMChallengeResponseParsed{}, err
	}
	if r.UserLen == 0 {
		return NTLMChallengeResponseParsed{}, errors.New("No repsponse data")
	}
	if int(r.NtOffset)+int(r.NtLen) > len(b) ||
		int(r.LmOffset)+int(r.LmLen) > len(b) ||
		int(r.UserOffset)+int(r.UserLen) > len(b) ||
		int(r.DomainOffset)+int(r.DomainLen) > len(b) {
		return NTLMChallengeResponseParsed{}, errors.New("response too short")
	}
	nthash := b[r.NtOffset : r.NtOffset+r.NtLen]
	if len(nthash) < 16 {
		return NTLMChallengeResponseParsed{}, errors.New("NTLMv2 hash too short")
	}
	serverChallenge, err := sr.serverChallenge()
	if err != nil {
		return NTLMChallengeResponseParsed{}, err
	}
	user := sanitizeNTLMString(b[r.UserOffset : r.UserOffset+r.UserLen])
	domain := sanitizeNTLMString(b[r.DomainOffset : r.DomainOffset+r.DomainLen])
	parsed := NTLMChallengeResponseParsed{
		Type:            NtlmV2,
		ServerChallenge: serverChallenge,
		User:            user,
		Domain:          domain,
		NtHashOne:       hex.EncodeToString(nthash[:16]),
		NtHashTwo:       hex.EncodeToString(nthash[16:]),
	}
	if !parsed.hasCompleteIdentity() {
		return NTLMChallengeResponseParsed{}, ErrIncompleteNTLMIdentity
	}
	return parsed, nil
}

func (sr NTLMChallengeResponse) isNtlmV1() bool {
	headerValues := sr.getResponseHeader()
	return headerValues.NtLen == 24
}

func (sr NTLMChallengeResponse) ParsedNtLMv1() (NTLMChallengeResponseParsed, error) {
	r, b, err := sr.parsedResponseHeader()
	if err != nil {
		return NTLMChallengeResponseParsed{}, err
	}
	if r.UserLen == 0 {
		return NTLMChallengeResponseParsed{}, errors.New("No repsponse data")
	}
	if int(r.UserOffset)+int(r.UserLen) > len(b) ||
		int(r.DomainOffset)+int(r.DomainLen) > len(b) ||
		int(r.LmOffset)+int(r.LmLen) > len(b) ||
		int(r.NtOffset)+int(r.NtLen) > len(b) {
		return NTLMChallengeResponseParsed{}, errors.New("response too short")
	}
	serverChallenge, err := sr.serverChallenge()
	if err != nil {
		return NTLMChallengeResponseParsed{}, err
	}
	user := sanitizeNTLMString(b[r.UserOffset : r.UserOffset+r.UserLen])
	domain := sanitizeNTLMString(b[r.DomainOffset : r.DomainOffset+r.DomainLen])
	parsed := NTLMChallengeResponseParsed{
		Type:            NtlmV1,
		ServerChallenge: serverChallenge,
		User:            user,
		Domain:          domain,
		LmHash:          hex.EncodeToString(b[r.LmOffset : r.LmOffset+r.LmLen]),
	}
	if !parsed.hasCompleteIdentity() {
		return NTLMChallengeResponseParsed{}, ErrIncompleteNTLMIdentity
	}
	return parsed, nil
}

func sanitizeNTLMString(b []byte) string {
	return strings.ReplaceAll(string(b), "\x00", "")
}

func (d NTLMChallengeResponseParsed) hasCompleteIdentity() bool {
	if d.User == "" || d.ServerChallenge == "" {
		return false
	}
	if d.Domain != "" {
		return true
	}
	// UPN and down-level qualified names carry the authority in User even
	// when the Type 3 DomainName field is empty.
	return strings.ContainsAny(d.User, `@\`)
}

func _uint32(b []byte, start, end int) uint32 {
	return binary.LittleEndian.Uint32(b[start:end])
}

func _uint16(b []byte, start, end int) uint16 {
	return binary.LittleEndian.Uint16(b[start:end])
}

func (sr NTLMChallengeResponse) getResponseHeader() NTLMResponseHeader {
	header, _, _ := sr.parsedResponseHeader()
	return header
}

func (sr NTLMChallengeResponse) parsedResponseHeader() (NTLMResponseHeader, []byte, error) {
	b, err := sr.decodeResponse()
	if err != nil {
		return NTLMResponseHeader{}, nil, err
	}
	if len(b) < NTLM_TYPE3_WORKSTN_OFFSET+6 {
		err := fmt.Errorf("%w: header is too short", ErrInvalidNTLMResponse)
		return NTLMResponseHeader{}, nil, err
	}
	if string(b[:len(ntlmSignature)]) != ntlmSignature {
		return NTLMResponseHeader{}, nil, fmt.Errorf("%w: bad signature", ErrInvalidNTLMResponse)
	}
	if messageType := _uint32(b, NTLM_TYPE_OFFSET, NTLM_TYPE_OFFSET+4); messageType != 3 {
		return NTLMResponseHeader{}, nil, fmt.Errorf("%w: unexpected message type %d", ErrInvalidNTLMResponse, messageType)
	}
	header := NTLMResponseHeader{
		Sig:          sanitizeNTLMString(b[NTLM_SIG_OFFSET : NTLM_SIG_OFFSET+8]),
		Type:         _uint32(b, NTLM_TYPE_OFFSET, NTLM_TYPE_OFFSET+4),
		LmLen:        _uint16(b, NTLM_TYPE3_LMRESP_OFFSET, NTLM_TYPE3_LMRESP_OFFSET+2),
		LmMax:        _uint16(b, NTLM_TYPE3_LMRESP_OFFSET+2, NTLM_TYPE3_LMRESP_OFFSET+4),
		LmOffset:     _uint16(b, NTLM_TYPE3_LMRESP_OFFSET+4, NTLM_TYPE3_LMRESP_OFFSET+6),
		NtLen:        _uint16(b, NTLM_TYPE3_NTRESP_OFFSET, NTLM_TYPE3_NTRESP_OFFSET+2),
		NtMax:        _uint16(b, NTLM_TYPE3_NTRESP_OFFSET+2, NTLM_TYPE3_NTRESP_OFFSET+4),
		NtOffset:     _uint16(b, NTLM_TYPE3_NTRESP_OFFSET+4, NTLM_TYPE3_NTRESP_OFFSET+6),
		DomainLen:    _uint16(b, NTLM_TYPE3_DOMAIN_OFFSET, NTLM_TYPE3_DOMAIN_OFFSET+2),
		DomainMax:    _uint16(b, NTLM_TYPE3_DOMAIN_OFFSET+2, NTLM_TYPE3_DOMAIN_OFFSET+4),
		DomainOffset: _uint16(b, NTLM_TYPE3_DOMAIN_OFFSET+4, NTLM_TYPE3_DOMAIN_OFFSET+6),
		UserLen:      _uint16(b, NTLM_TYPE3_USER_OFFSET, NTLM_TYPE3_USER_OFFSET+2),
		UserMax:      _uint16(b, NTLM_TYPE3_USER_OFFSET+2, NTLM_TYPE3_USER_OFFSET+4),
		UserOffset:   _uint16(b, NTLM_TYPE3_USER_OFFSET+4, NTLM_TYPE3_USER_OFFSET+6),
		HostLen:      _uint16(b, NTLM_TYPE3_WORKSTN_OFFSET, NTLM_TYPE3_WORKSTN_OFFSET+2),
		HostMax:      _uint16(b, NTLM_TYPE3_WORKSTN_OFFSET+2, NTLM_TYPE3_WORKSTN_OFFSET+4),
		HostOffset:   _uint16(b, NTLM_TYPE3_WORKSTN_OFFSET+4, NTLM_TYPE3_WORKSTN_OFFSET+6),
	}
	return header, b, nil
}

func (data NTLMChallengeResponseParsed) LcString() string {
	// NTLM v1 in .lc format
	if data.Type == NtlmV1 {
		return data.User + "::" + data.Domain + ":" + data.LmHash + ":" + data.ServerChallenge + "\n"
	}
	return data.User + "::" + data.Domain + ":" + data.ServerChallenge + ":" + data.NtHashOne + ":" + data.NtHashTwo + "\n"
}
