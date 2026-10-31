package decoder

import (
	"errors"
	"fmt"
)

// TZSP protocol constants.
const (
	tzspVersion    = 0x01
	tzspTypePacket = 0x00
	tzspTagEnd     = 0x01
	tzspTagPadding = 0x00
	tzspHeaderLen  = 4

	// minPayloadLen is the minimum size of a decapsulated payload
	// (a minimal IPv4 header).
	minPayloadLen = 20
)

// Sentinel errors returned by DecodeTZSP.
var (
	ErrPacketTooShort = errors.New("packet too short")
	ErrInvalidVersion = errors.New("invalid TZSP version")
	ErrNotPacketType  = errors.New("not a packet type")
	ErrTruncatedTag   = errors.New("truncated tag")
	ErrTagOverflow    = errors.New("tag extends beyond packet")
	ErrNoPayload      = errors.New("no payload after TZSP header")
)

// DecodeTZSP extracts the encapsulated payload from a TZSP packet.
//
// The TZSP header is 4 bytes: version (1), type (1), and the 2-byte
// encapsulated protocol field. It is followed by a sequence of tags
// terminated by the end tag. The bytes after the end tag are the
// encapsulated packet (typically an Ethernet frame; use -linktype raw
// if the sender encapsulates raw IP).
//
// Only received packets (type 0x00) are decoded. TX, configuration,
// keepalive and port packets are rejected with ErrNotPacketType.
func DecodeTZSP(data []byte) ([]byte, error) {
	if len(data) < tzspHeaderLen {
		return nil, fmt.Errorf("%w: %d bytes", ErrPacketTooShort, len(data))
	}
	if data[0] != tzspVersion {
		return nil, fmt.Errorf("%w: %d", ErrInvalidVersion, data[0])
	}
	if data[1] != tzspTypePacket {
		return nil, fmt.Errorf("%w: %d", ErrNotPacketType, data[1])
	}

	offset := tzspHeaderLen
	for offset < len(data) {
		tag := data[offset]
		offset++

		switch tag {
		case tzspTagEnd:
			return payload(data, offset)
		case tzspTagPadding:
			continue
		}

		if offset >= len(data) {
			return nil, fmt.Errorf("%w at offset %d", ErrTruncatedTag, offset)
		}
		tagLen := int(data[offset])
		offset++

		offset += tagLen
		if offset > len(data) {
			return nil, fmt.Errorf("%w at offset %d", ErrTagOverflow, offset)
		}
	}

	return payload(data, offset)
}

// payload returns the bytes after the TZSP header and tags.
func payload(data []byte, offset int) ([]byte, error) {
	if offset >= len(data) {
		return nil, ErrNoPayload
	}
	return data[offset:], nil
}
