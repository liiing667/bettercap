package packets

import (
	"bytes"
	"errors"
	"testing"

	"github.com/mdlayher/dhcp6"
)

func TestDHCP6OptDNSServers(t *testing.T) {
	exp := 23
	got := DHCP6OptDNSServers
	if exp != got {
		t.Fatalf("expected '%v', got '%v'", exp, got)
	}
}

func TestDHCP6OptDNSDomains(t *testing.T) {
	exp := 24
	got := DHCP6OptDNSDomains
	if exp != got {
		t.Fatalf("expected '%v', got '%v'", exp, got)
	}
}

func TestDHCP6OptClientFQDN(t *testing.T) {
	exp := 39
	got := DHCP6OptClientFQDN
	if exp != got {
		t.Fatalf("expected '%v', got '%v'", exp, got)
	}
}

func TestIPv6Prefix(t *testing.T) {
	exp := "fe80::"
	got := IPv6Prefix
	if exp != got {
		t.Fatalf("expected '%v', got '%v'", exp, got)
	}
}

func TestDHCP6EncodeList(t *testing.T) {
	domains := []string{"microsoft.com", "google.com", "facebook.com"}

	encoded := DHCP6EncodeList(domains)

	if len(encoded) <= 0 {
		t.Error("unable to dhcp6 encode a given list")
	}
}

func TestDHCP6For(t *testing.T) {
	mesg := dhcp6.MessageTypeSolicit
	pakt := dhcp6.Packet{Options: dhcp6.Options{}}
	pakt.Options.AddRaw(dhcp6.OptionClientID, []byte{})
	duid := []byte{}

	err, _ := DHCP6For(mesg, pakt, duid)

	if err != nil {
		t.Error(err)
	}
}

func TestDHCP6ForRejectsMismatchedClientID(t *testing.T) {
	clientID := []byte{0x00, 0x01, 0xaa, 0xbb}
	callerDUID := []byte{0x00, 0x03, 0xcc, 0xdd}

	request := dhcp6.Packet{Options: dhcp6.Options{}}
	request.Options.AddRaw(dhcp6.OptionClientID, clientID)

	err, response := DHCP6For(dhcp6.MessageTypeSolicit, request, callerDUID)
	if err == nil {
		t.Fatal("DHCP6For accepted a client id that differs from the caller DUID")
	}
	if !errors.Is(err, ErrClientIDMismatch) {
		t.Fatalf("expected ErrClientIDMismatch, got %v", err)
	}
	if len(response.Options) != 0 {
		t.Fatalf("mismatched request produced response options: %v", response.Options)
	}

	var mismatch *DHCP6ClientIDMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected mismatch details, got %T", err)
	}
	if !bytes.Equal(mismatch.ClientID, clientID) || !bytes.Equal(mismatch.DUID, callerDUID) {
		t.Fatalf("mismatch error lost identities: client id %x, duid %x", mismatch.ClientID, mismatch.DUID)
	}
}

func TestDHCP6ForAcceptsMatchingClientID(t *testing.T) {
	clientID := []byte{0x00, 0x01, 0xaa, 0xbb}

	request := dhcp6.Packet{
		TransactionID: [3]byte{0x01, 0x02, 0x03},
		Options:       dhcp6.Options{},
	}
	request.Options.AddRaw(dhcp6.OptionClientID, clientID)

	err, response := DHCP6For(dhcp6.MessageTypeSolicit, request, clientID)
	if err != nil {
		t.Fatal(err)
	}
	if response.TransactionID != request.TransactionID {
		t.Fatalf("transaction id changed: got %v, want %v", response.TransactionID, request.TransactionID)
	}
	for _, option := range []dhcp6.OptionCode{dhcp6.OptionClientID, dhcp6.OptionServerID} {
		raw, found := response.Options[option]
		if !found || len(raw) != 1 || !bytes.Equal(raw[0], clientID) {
			t.Fatalf("option %d = %x, want %x", option, raw, clientID)
		}
	}
}

func TestDHCP6ForClientKeepsServerIdentitySeparate(t *testing.T) {
	clientID := []byte{0x00, 0x01, 0xaa, 0xbb}
	serverDUID := []byte{0x00, 0x03, 0xcc, 0xdd}

	request := dhcp6.Packet{Options: dhcp6.Options{}}
	request.Options.AddRaw(dhcp6.OptionClientID, clientID)

	err, response := DHCP6ForClient(dhcp6.MessageTypeAdvertise, request, clientID, serverDUID)
	if err != nil {
		t.Fatal(err)
	}
	if raw := response.Options[dhcp6.OptionClientID]; len(raw) != 1 || !bytes.Equal(raw[0], clientID) {
		t.Fatalf("client id = %x, want %x", raw, clientID)
	}
	if raw := response.Options[dhcp6.OptionServerID]; len(raw) != 1 || !bytes.Equal(raw[0], serverDUID) {
		t.Fatalf("server id = %x, want %x", raw, serverDUID)
	}
}

func TestDHCP6ClientIDRejectsMissingOption(t *testing.T) {
	_, err := DHCP6ClientID(dhcp6.Packet{Options: dhcp6.Options{}})
	if !errors.Is(err, ErrNoCID) {
		t.Fatalf("expected ErrNoCID, got %v", err)
	}
}

func relayForward(t *testing.T, clientID, relayID []byte) dhcp6.Packet {
	t.Helper()

	client := dhcp6.Packet{Options: dhcp6.Options{}}
	client.Options.AddRaw(dhcp6.OptionClientID, clientID)
	clientRaw, err := client.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	relay := dhcp6.Packet{MessageType: dhcp6.MessageTypeRelayForw, Options: dhcp6.Options{}}
	relay.Options.AddRaw(dhcp6.OptionRelayMsg, clientRaw)
	relay.Options.AddRaw(dhcp6OptionRelayID, relayID)
	return relay
}

func TestDHCP6ForClientAllowsRelayCallerIdentity(t *testing.T) {
	clientID := []byte{0x00, 0x01, 0xaa, 0xbb}
	relayID := []byte{0x00, 0x03, 0xcc, 0xdd}
	serverDUID := []byte{0x00, 0x03, 0xee, 0xff}
	relay := relayForward(t, clientID, relayID)

	err, response := DHCP6ForClient(dhcp6.MessageTypeAdvertise, relay, relayID, serverDUID)
	if err != nil {
		t.Fatalf("legitimate relay flow rejected: %v", err)
	}
	if raw := response.Options[dhcp6.OptionClientID]; len(raw) != 1 || !bytes.Equal(raw[0], clientID) {
		t.Fatalf("relayed client id = %x, want %x", raw, clientID)
	}

	// The original client's DUID is accepted as well, for callers that have
	// already resolved the relayed message to its client.
	if err, _ := DHCP6ForClient(dhcp6.MessageTypeAdvertise, relay, clientID, serverDUID); err != nil {
		t.Fatalf("relayed client identity rejected: %v", err)
	}

	otherDUID := []byte{0x00, 0x03, 0x11, 0x22}
	if err, _ := DHCP6ForClient(dhcp6.MessageTypeAdvertise, relay, otherDUID, serverDUID); !errors.Is(err, ErrClientIDMismatch) {
		t.Fatalf("relay flow with an unrelated DUID was accepted: %v", err)
	}
}
