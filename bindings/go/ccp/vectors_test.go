package ccp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const intentSpecJSON = `{"confirmation":"grant-policy","required_capabilities":["store.read"]}`
const paramsSchemaJSON = `{"additionalProperties":false,"properties":{"item_id":{"type":"string"}},"required":["item_id"],"type":"object"}`

func readJSON(t *testing.T, relative string, target any) {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, relative))
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("parse %s: %v", relative, err)
	}
}

func expectProtocolError(t *testing.T, err error, code string) {
	t.Helper()
	protocol, ok := err.(*ProtocolError)
	if !ok {
		t.Fatalf("expected protocol error %s, got %v", code, err)
	}
	if protocol.Code != code {
		t.Fatalf("expected protocol error %s, got %s", code, protocol.Code)
	}
}

type canonicalFile struct {
	Vectors []struct {
		ID          string `json:"id"`
		Document    string `json:"document"`
		Expected    string `json:"expected_canonical"`
		ExpectError string `json:"expect_error"`
	} `json:"vectors"`
}

func TestCanonicalVectors(t *testing.T) {
	paths := []string{
		"test-vectors/canonical-json.json",
		"test-vectors/v2/canonical-json.json",
	}
	count := 0
	for _, path := range paths {
		var file canonicalFile
		readJSON(t, path, &file)
		for _, vector := range file.Vectors {
			vector := vector
			count++
			t.Run(path+"/"+vector.ID, func(t *testing.T) {
				got, err := Canonicalize(vector.Document)
				if vector.ExpectError != "" {
					expectProtocolError(t, err, vector.ExpectError)
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got != vector.Expected {
					t.Fatalf("expected %q, got %q", vector.Expected, got)
				}
			})
		}
	}
	if count != 39 {
		t.Fatalf("expected 39 canonical cases, ran %d", count)
	}
}

type validationContext struct {
	Now      string                 `json:"now"`
	Seen     []string               `json:"seen"`
	Counters map[string]json.Number `json:"counters"`
}

type validationFile struct {
	Vectors []struct {
		ID       string            `json:"id"`
		Grant    json.RawMessage   `json:"grant"`
		Signal   json.RawMessage   `json:"signal"`
		Signer   string            `json:"signer"`
		Context  validationContext `json:"context"`
		Expected string            `json:"expected"`
	} `json:"vectors"`
}

func TestValidationVectors(t *testing.T) {
	paths := []string{
		"test-vectors/validation.json",
		"test-vectors/v2/validation.json",
	}
	count := 0
	for _, path := range paths {
		var file validationFile
		readJSON(t, path, &file)
		for _, vector := range file.Vectors {
			vector := vector
			count++
			t.Run(path+"/"+vector.ID, func(t *testing.T) {
				got, err := Decide(DecisionInput{
					Grant:        vector.Grant,
					Signal:       vector.Signal,
					Signer:       vector.Signer,
					Now:          vector.Context.Now,
					Seen:         vector.Context.Seen,
					Counters:     vector.Context.Counters,
					IntentSpec:   json.RawMessage(intentSpecJSON),
					ParamsSchema: json.RawMessage(paramsSchemaJSON),
				})
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got != vector.Expected {
					t.Fatalf("expected %s, got %s", vector.Expected, got)
				}
			})
		}
	}
	if count != 35 {
		t.Fatalf("expected 35 validation cases, ran %d", count)
	}
}

func TestStateMachineVectors(t *testing.T) {
	var file struct {
		Vectors []struct {
			ID    string `json:"id"`
			From  string `json:"from"`
			Event string `json:"event"`
			To    string `json:"to"`
		} `json:"vectors"`
	}
	readJSON(t, "test-vectors/state-machine.json", &file)
	for _, vector := range file.Vectors {
		vector := vector
		t.Run(vector.ID, func(t *testing.T) {
			from := vector.From
			got, err := NextState(&from, vector.Event)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != vector.To {
				t.Fatalf("expected %s, got %s", vector.To, got)
			}
		})
	}
	if len(file.Vectors) != 10 {
		t.Fatalf("expected 10 state cases, ran %d", len(file.Vectors))
	}
}

func TestEd25519KnownAnswers(t *testing.T) {
	var file struct {
		Vectors []struct {
			ID             string `json:"id"`
			SecretKeyHex   string `json:"secret_key_hex"`
			PublicKeyHex   string `json:"public_key_hex"`
			KeyID          string `json:"key_id"`
			MessageHex     string `json:"message_hex"`
			SignatureHex   string `json:"signature_hex"`
			SignatureField string `json:"signature_field"`
		} `json:"kat_vectors"`
	}
	readJSON(t, "test-vectors/ed25519.json", &file)
	for _, vector := range file.Vectors {
		vector := vector
		t.Run(vector.ID, func(t *testing.T) {
			signed, err := Sign(vector.SecretKeyHex, vector.MessageHex)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			if signed.PublicKeyHex != vector.PublicKeyHex {
				t.Fatalf("public key: expected %s, got %s", vector.PublicKeyHex, signed.PublicKeyHex)
			}
			if signed.KeyID != vector.KeyID {
				t.Fatalf("key id: expected %s, got %s", vector.KeyID, signed.KeyID)
			}
			if signed.SignatureHex != vector.SignatureHex {
				t.Fatalf("signature: expected %s, got %s", vector.SignatureHex, signed.SignatureHex)
			}
			if signed.SignatureField != vector.SignatureField {
				t.Fatalf("signature field: expected %s, got %s", vector.SignatureField, signed.SignatureField)
			}
			ok, err := Verify(vector.PublicKeyHex, vector.MessageHex, vector.SignatureField)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if !ok {
				t.Fatal("signature did not verify")
			}
		})
	}
	if len(file.Vectors) != 3 {
		t.Fatalf("expected 3 KAT cases, ran %d", len(file.Vectors))
	}
}

func TestEd25519SigningVectors(t *testing.T) {
	var file struct {
		Vectors []struct {
			ID                 string `json:"id"`
			SeedHex            string `json:"seed_hex"`
			PublicKeyHex       string `json:"public_key_hex"`
			KeyID              string `json:"key_id"`
			Document           string `json:"document"`
			SigningInputSHA256 string `json:"signing_input_sha256"`
			SignatureField     string `json:"signature_field"`
			Wire               string `json:"wire"`
		} `json:"signing_vectors"`
	}
	readJSON(t, "test-vectors/ed25519.json", &file)
	for _, vector := range file.Vectors {
		vector := vector
		t.Run(vector.ID, func(t *testing.T) {
			signed, err := SignDocument(vector.Document, vector.SeedHex)
			if err != nil {
				t.Fatalf("sign document: %v", err)
			}
			if signed.PublicKeyHex != vector.PublicKeyHex {
				t.Fatalf("public key: expected %s, got %s", vector.PublicKeyHex, signed.PublicKeyHex)
			}
			if signed.KeyID != vector.KeyID {
				t.Fatalf("key id: expected %s, got %s", vector.KeyID, signed.KeyID)
			}
			if signed.SigningInputSHA256 != vector.SigningInputSHA256 {
				t.Fatalf("signing hash: expected %s, got %s", vector.SigningInputSHA256, signed.SigningInputSHA256)
			}
			if signed.SignatureField != vector.SignatureField {
				t.Fatalf("signature field: expected %s, got %s", vector.SignatureField, signed.SignatureField)
			}
			if signed.Wire != vector.Wire {
				t.Fatalf("wire: expected %s, got %s", vector.Wire, signed.Wire)
			}
		})
	}
	if len(file.Vectors) != 2 {
		t.Fatalf("expected 2 signing cases, ran %d", len(file.Vectors))
	}
}
