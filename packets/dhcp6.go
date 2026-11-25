package packets

import (
	"bytes"
	"errors"
	"fmt"
	// TODO: refactor to use gopacket when gopacket folks
	// will fix this > https://github.com/google/gopacket/issues/334
	"github.com/mdlayher/dhcp6"
)

const DHCP6OptDNSServers = 23
const DHCP6OptDNSDomains = 24
const DHCP6OptClientFQDN = 39

// OptionRelayID is not exposed by the mdlayher/dhcp6 version used here.
const dhcp6OptionRelayID dhcp6.OptionCode = 37

// maxDHCP6RelayDepth bounds how many nested Relay-Message options are
// unwrapped while looking for the client identity.
const maxDHCP6RelayDepth = 8

// link-local
const IPv6Prefix = "fe80::"

var (
	ErrNoCID            = errors.New("Unexpected DHCPv6 packet, could not find client id.")
	ErrClientIDMismatch = errors.New("DHCPv6 client id does not match the expected DUID")
)

// DHCP6ClientIDMismatchError reports that the ClientID carried by a request
// does not identify the same client as the DUID supplied by the caller.  Both
// values are kept in the error so callers can audit the rejected transaction
// without having to look at the original packet again.
type DHCP6ClientIDMismatchError struct {
	ClientID []byte
	DUID     []byte
}

func (e *DHCP6ClientIDMismatchError) Error() string {
	return fmt.Sprintf("%s (client id %x, duid %x)", ErrClientIDMismatch, e.ClientID, e.DUID)
}

// Unwrap makes errors.Is(err, ErrClientIDMismatch) work as expected.
func (e *DHCP6ClientIDMismatchError) Unwrap() error {
	return ErrClientIDMismatch
}

func DHCP6EncodeList(elements []string) (encoded []byte) {
	encoded = make([]byte, 0)

	for _, elem := range elements {
		// this would be worth fuzzing btw
		encoded = append(encoded, byte(len(elem)&0xff))
		encoded = append(encoded, []byte(elem)...)
	}

	return
}

// DHCP6ClientID returns a copy of the ClientID (the client's DUID) carried by
// a DHCPv6 message.  Relay-Forward messages carry the original client message
// in a Relay-Message option, so those are unwrapped before looking for the
// ClientID.  A missing option is reported as ErrNoCID so callers never build a
// response for an unidentified client.
func DHCP6ClientID(p dhcp6.Packet) ([]byte, error) {
	return dhcp6ClientID(p, 0)
}

func dhcp6ClientID(p dhcp6.Packet, depth int) ([]byte, error) {
	raw, found := p.Options[dhcp6.OptionClientID]
	if found && len(raw) > 0 {
		return append([]byte(nil), raw[0]...), nil
	}

	if depth >= maxDHCP6RelayDepth {
		return nil, ErrNoCID
	}

	relayMsg, found := p.Options[dhcp6.OptionRelayMsg]
	if !found || len(relayMsg) < 1 || len(relayMsg[0]) == 0 {
		return nil, ErrNoCID
	}

	var inner dhcp6.Packet
	if err := inner.UnmarshalBinary(relayMsg[0]); err != nil {
		return nil, err
	}

	return dhcp6ClientID(inner, depth+1)
}

func dhcp6RelayID(p dhcp6.Packet) ([]byte, bool) {
	raw, found := p.Options[dhcp6OptionRelayID]
	if !found || len(raw) < 1 {
		return nil, false
	}
	return raw[0], true
}

func dhcp6IsRelayed(p dhcp6.Packet) bool {
	if _, found := p.Options[dhcp6.OptionClientID]; found {
		return false
	}
	_, found := p.Options[dhcp6.OptionRelayMsg]
	return found
}

// DHCP6For builds a response for the client identified by duid.
//
// The request must carry exactly that client identifier.  If it does not, no
// response is produced and a DHCP6ClientIDMismatchError is returned; this
// prevents a spoofed reply from being addressed to one client while carrying
// another client's identity.  A relayed request is also accepted when duid is
// the relay's Relay-ID; the response stays bound to the relayed client's
// ClientID.  For backwards compatibility the supplied DUID is also used as the
// server identifier.  Callers that need a distinct server identity should use
// DHCP6ForClient.
func DHCP6For(what dhcp6.MessageType, to dhcp6.Packet, duid []byte) (err error, p dhcp6.Packet) {
	return DHCP6ForClient(what, to, duid, duid)
}

// DHCP6ForClient builds a response bound to clientDUID while advertising
// serverDUID as the DHCPv6 server identifier.  Requiring the two identities to
// be passed explicitly keeps the destination client and the responding server
// from being confused with each other.  On any validation failure the
// returned packet is left without options, so a partial response can never be
// serialized or sent.
func DHCP6ForClient(what dhcp6.MessageType, to dhcp6.Packet, clientDUID, serverDUID []byte) (err error, p dhcp6.Packet) {
	p = dhcp6.Packet{
		MessageType:   what,
		TransactionID: to.TransactionID,
		Options:       make(dhcp6.Options),
	}

	rawCID, err := DHCP6ClientID(to)
	if err != nil {
		return err, p
	}

	if !bytes.Equal(rawCID, clientDUID) {
		// In a relay exchange the caller's DUID belongs to the relay agent,
		// while rawCID belongs to the original client.  They are allowed to
		// differ, but only when the caller's DUID is actually the relay's
		// Relay-ID.
		relayID, hasRelayID := dhcp6RelayID(to)
		if !dhcp6IsRelayed(to) || !hasRelayID || !bytes.Equal(relayID, clientDUID) {
			return &DHCP6ClientIDMismatchError{
				ClientID: rawCID,
				DUID:     append([]byte(nil), clientDUID...),
			}, p
		}
	}

	p.Options.AddRaw(dhcp6.OptionClientID, rawCID)
	p.Options.AddRaw(dhcp6.OptionServerID, serverDUID)

	return nil, p
}
