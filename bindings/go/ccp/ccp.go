// Package ccp binds the portable CCP kernel over its C ABI.
package ccp

/*
#cgo CFLAGS: -I${SRCDIR}/../../../kernel/include
#cgo LDFLAGS: -L${SRCDIR}/../../../kernel/target/release -l:libccp_kernel.a -lpthread -ldl -lm
#include <stdlib.h>
#include "ccp.h"
*/
import "C"

import (
	"encoding/json"
	"errors"
	"unsafe"
)

// ProtocolError is a §10.4 rejection code or a canonical parsing error.
type ProtocolError struct {
	Code string
}

func (e *ProtocolError) Error() string { return e.Code }

type envelope struct {
	OK    bool            `json:"ok"`
	Value json.RawMessage `json:"value"`
	Error string          `json:"error"`
}

type opCode int

const (
	opCanonicalize opCode = iota
	opDecide
	opNextState
	opSign
	opVerify
	opSignDocument
)

func invoke(op opCode, input []byte) (envelope, error) {
	var pointer *C.uint8_t
	length := C.size_t(len(input))
	if len(input) > 0 {
		pointer = C.ccp_alloc(length)
		if pointer == nil {
			return envelope{}, errors.New("ccp_alloc failed")
		}
		copy(unsafe.Slice((*byte)(unsafe.Pointer(pointer)), len(input)), input)
	}

	var code C.int32_t
	switch op {
	case opCanonicalize:
		code = C.ccp_canonicalize(pointer, length)
	case opDecide:
		code = C.ccp_decide(pointer, length)
	case opNextState:
		code = C.ccp_next_state(pointer, length)
	case opSign:
		code = C.ccp_sign(pointer, length)
	case opVerify:
		code = C.ccp_verify(pointer, length)
	case opSignDocument:
		code = C.ccp_sign_document(pointer, length)
	default:
		return envelope{}, errors.New("unknown operation")
	}

	if pointer != nil {
		C.ccp_free(pointer, length)
	}

	raw := C.GoBytes(
		unsafe.Pointer(C.ccp_result_ptr()),
		C.int(C.ccp_result_len()),
	)
	var result envelope
	if err := json.Unmarshal(raw, &result); err != nil {
		return envelope{}, err
	}
	if (code == 0) != result.OK {
		return envelope{}, errors.New("kernel envelope mismatch")
	}
	return result, nil
}

func resultError(result envelope) error {
	if result.OK {
		return nil
	}
	return &ProtocolError{Code: result.Error}
}

func fromEnvelope(result envelope, value any) error {
	if err := resultError(result); err != nil {
		return err
	}
	return json.Unmarshal(result.Value, value)
}

// DecisionInput mirrors the kernel's `ccp_decide` envelope.
type DecisionInput struct {
	Grant        json.RawMessage        `json:"grant"`
	Signal       json.RawMessage        `json:"signal"`
	Signer       string                 `json:"signer"`
	Now          string                 `json:"now"`
	Seen         []string               `json:"seen"`
	Counters     map[string]json.Number `json:"counters"`
	IntentSpec   json.RawMessage        `json:"intent_spec"`
	ParamsSchema json.RawMessage        `json:"params_schema"`
}

// SignResult is the output of a raw Ed25519 signature.
type SignResult struct {
	PublicKeyHex   string `json:"public_key_hex"`
	KeyID          string `json:"key_id"`
	SignatureHex   string `json:"signature_hex"`
	SignatureField string `json:"signature_field"`
}

// SignDocumentResult is the output of signing a CCP document.
type SignDocumentResult struct {
	PublicKeyHex       string `json:"public_key_hex"`
	KeyID              string `json:"key_id"`
	SignatureField     string `json:"signature_field"`
	SigningInputSHA256 string `json:"signing_input_sha256"`
	Wire               string `json:"wire"`
}

// Canonicalize returns the strict canonical form of a JSON document.
func Canonicalize(document string) (string, error) {
	result, err := invoke(opCanonicalize, []byte(document))
	if err != nil {
		return "", err
	}
	var value string
	if err := fromEnvelope(result, &value); err != nil {
		return "", err
	}
	return value, nil
}

// Decide runs the §10.3 decision.
func Decide(input DecisionInput) (string, error) {
	payload, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	result, err := invoke(opDecide, payload)
	if err != nil {
		return "", err
	}
	var value string
	if err := fromEnvelope(result, &value); err != nil {
		return "", err
	}
	return value, nil
}

// NextState returns the §26.3 state after an event. A nil `from` means start.
func NextState(from *string, event string) (string, error) {
	payload, err := json.Marshal(map[string]any{"from": from, "event": event})
	if err != nil {
		return "", err
	}
	result, err := invoke(opNextState, payload)
	if err != nil {
		return "", err
	}
	var value string
	if err := fromEnvelope(result, &value); err != nil {
		return "", err
	}
	return value, nil
}

// Sign signs raw bytes with an Ed25519 seed.
func Sign(seedHex, messageHex string) (SignResult, error) {
	payload, err := json.Marshal(map[string]string{
		"seed_hex":    seedHex,
		"message_hex": messageHex,
	})
	if err != nil {
		return SignResult{}, err
	}
	result, err := invoke(opSign, payload)
	if err != nil {
		return SignResult{}, err
	}
	var value SignResult
	if err := fromEnvelope(result, &value); err != nil {
		return SignResult{}, err
	}
	return value, nil
}

// Verify checks an Ed25519 signature.
func Verify(publicKeyHex, messageHex, signatureField string) (bool, error) {
	payload, err := json.Marshal(map[string]string{
		"public_key_hex":  publicKeyHex,
		"message_hex":     messageHex,
		"signature_field": signatureField,
	})
	if err != nil {
		return false, err
	}
	result, err := invoke(opVerify, payload)
	if err != nil {
		return false, err
	}
	var value bool
	if err := fromEnvelope(result, &value); err != nil {
		return false, err
	}
	return value, nil
}

// SignDocument canonicalizes, signs, and returns the wire form.
func SignDocument(document, seedHex string) (SignDocumentResult, error) {
	payload, err := json.Marshal(map[string]string{
		"document": document,
		"seed_hex": seedHex,
	})
	if err != nil {
		return SignDocumentResult{}, err
	}
	result, err := invoke(opSignDocument, payload)
	if err != nil {
		return SignDocumentResult{}, err
	}
	var value SignDocumentResult
	if err := fromEnvelope(result, &value); err != nil {
		return SignDocumentResult{}, err
	}
	return value, nil
}
