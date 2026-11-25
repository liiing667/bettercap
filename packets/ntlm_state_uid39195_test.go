package packets

import (
	"encoding/base64"
	"encoding/binary"
	"testing"
)

func ntlmUID39195UTF16(s string) []byte {
	out := make([]byte, 0, 2*len(s))
	for _, r := range s {
		var encoded [2]byte
		binary.LittleEndian.PutUint16(encoded[:], uint16(r))
		out = append(out, encoded[0], encoded[1])
	}
	return out
}

func ntlmUID39195Field(b []byte, offset, length, dataOffset int) {
	binary.LittleEndian.PutUint16(b[offset:offset+2], uint16(length))
	binary.LittleEndian.PutUint16(b[offset+2:offset+4], uint16(length))
	binary.LittleEndian.PutUint32(b[offset+4:offset+8], uint32(dataOffset))
}

func ntlmUID39195Challenge() string {
	b := make([]byte, NTLM_TYPE2_DATA_OFFSET)
	copy(b[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(b[NTLM_TYPE_OFFSET:NTLM_TYPE_OFFSET+4], 2)
	for i := 0; i < 8; i++ {
		b[NTLM_TYPE2_CHALLENGE_OFFSET+i] = byte(0x90 + i)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func ntlmUID39195Response(ntLength int, domain, user string) string {
	domainBytes := ntlmUID39195UTF16(domain)
	userBytes := ntlmUID39195UTF16(user)
	lmBytes := make([]byte, 24)
	ntBytes := make([]byte, ntLength)

	offset := NTLM_TYPE3_DATA_OFFSET
	domainOffset := offset
	offset += len(domainBytes)
	userOffset := offset
	offset += len(userBytes)
	lmOffset := offset
	offset += len(lmBytes)
	ntOffset := offset
	offset += len(ntBytes)

	b := make([]byte, offset)
	copy(b[0:8], ntlmSignature)
	binary.LittleEndian.PutUint32(b[NTLM_TYPE_OFFSET:NTLM_TYPE_OFFSET+4], 3)
	ntlmUID39195Field(b, NTLM_TYPE3_LMRESP_OFFSET, len(lmBytes), lmOffset)
	ntlmUID39195Field(b, NTLM_TYPE3_NTRESP_OFFSET, len(ntBytes), ntOffset)
	ntlmUID39195Field(b, NTLM_TYPE3_DOMAIN_OFFSET, len(domainBytes), domainOffset)
	ntlmUID39195Field(b, NTLM_TYPE3_USER_OFFSET, len(userBytes), userOffset)

	copy(b[domainOffset:], domainBytes)
	copy(b[userOffset:], userBytes)
	copy(b[lmOffset:], lmBytes)
	copy(b[ntOffset:], ntBytes)

	return base64.StdEncoding.EncodeToString(b)
}

func TestNTLMStateRejectsMalformedChallengeUID39195(t *testing.T) {
	state := NewNTLMState()
	state.AddServerResponse(42, "not-base64!")

	called := false
	state.AddClientResponse(42, ntlmUID39195Response(48, "CORP", "alice"), func(NTLMChallengeResponseParsed) {
		called = true
	})

	if called {
		t.Fatal("callback was invoked for a malformed challenge")
	}
	if len(state.Pairs) != 0 {
		t.Fatalf("malformed challenge produced %d trusted pairs", len(state.Pairs))
	}
}

func TestNTLMStateRejectsMalformedPairUID39195(t *testing.T) {
	state := NewNTLMState()
	state.AddServerResponse(42, "not-base64!")

	called := false
	state.AddClientResponse(42, "also-not-base64!", func(NTLMChallengeResponseParsed) {
		called = true
	})

	if called || len(state.Pairs) != 0 {
		t.Fatalf("malformed pair accepted: called=%v pairs=%d", called, len(state.Pairs))
	}
}

func TestNTLMStateFailedPairLeavesExistingPairUID39195(t *testing.T) {
	state := NewNTLMState()
	challenge := ntlmUID39195Challenge()
	validResponse := ntlmUID39195Response(48, "CORP", "alice")

	state.AddServerResponse(7, challenge)
	state.AddClientResponse(7, validResponse, func(NTLMChallengeResponseParsed) {})

	state.AddServerResponse(8, "not-base64!")
	state.AddClientResponse(8, "also-not-base64!", func(NTLMChallengeResponseParsed) {
		t.Fatal("callback invoked for invalid second pair")
	})

	if len(state.Pairs) != 1 {
		t.Fatalf("got %d pairs after failed second pair, want 1", len(state.Pairs))
	}
	if state.Pairs[0].Challenge != challenge || state.Pairs[0].Response != validResponse {
		t.Fatal("existing trusted pair was modified")
	}
}

func TestNTLMStateAcceptsCompleteV1AndV2PairsUID39195(t *testing.T) {
	for _, tc := range []struct {
		name     string
		ntLength int
		wantType int
	}{
		{name: "v1", ntLength: 24, wantType: NtlmV1},
		{name: "v2", ntLength: 48, wantType: NtlmV2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := NewNTLMState()
			state.AddServerResponse(9, ntlmUID39195Challenge())

			calls := 0
			state.AddClientResponse(9, ntlmUID39195Response(tc.ntLength, "CORP", "alice"), func(data NTLMChallengeResponseParsed) {
				calls++
				if data.Type != tc.wantType {
					t.Fatalf("type = %d, want %d", data.Type, tc.wantType)
				}
				if data.User != "alice" || data.Domain != "CORP" {
					t.Fatalf("identity = %q/%q", data.Domain, data.User)
				}
				if len(data.ServerChallenge) != 16 {
					t.Fatalf("server challenge = %q", data.ServerChallenge)
				}
			})

			if calls != 1 {
				t.Fatalf("callback calls = %d, want 1", calls)
			}
			if len(state.Pairs) != 1 {
				t.Fatalf("pairs = %d, want 1", len(state.Pairs))
			}
		})
	}
}

func TestNTLMStateRejectsIncompleteIdentityUID39195(t *testing.T) {
	state := NewNTLMState()
	state.AddServerResponse(10, ntlmUID39195Challenge())

	called := false
	state.AddClientResponse(10, ntlmUID39195Response(48, "", "alice"), func(NTLMChallengeResponseParsed) {
		called = true
	})

	if called || len(state.Pairs) != 0 {
		t.Fatalf("incomplete identity accepted: called=%v pairs=%d", called, len(state.Pairs))
	}
}

func TestNTLMStateAcceptsUPNWithoutDomainFieldUID39195(t *testing.T) {
	state := NewNTLMState()
	state.AddServerResponse(11, ntlmUID39195Challenge())

	called := false
	state.AddClientResponse(11, ntlmUID39195Response(48, "", "alice@corp.example"), func(data NTLMChallengeResponseParsed) {
		called = true
		if data.User != "alice@corp.example" {
			t.Fatalf("user = %q", data.User)
		}
	})

	if !called || len(state.Pairs) != 1 {
		t.Fatalf("UPN pair rejected: called=%v pairs=%d", called, len(state.Pairs))
	}
}
