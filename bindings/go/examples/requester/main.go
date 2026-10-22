// Sign a manifest and a signal through the CCP kernel.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"ccp/bindings/go/ccp"
)

const seedHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func main() {
	identity, err := ccp.Sign(seedHex, "")
	must(err)

	manifest := map[string]any{
		"ccp": "0.5-draft",
		"provider": map[string]any{
			"id":   identity.KeyID,
			"name": "Example Service",
		},
		"version": 1,
		"intents": map[string]any{
			"example.lookup": map[string]any{
				"description":           "Look up one item requested by the consumer",
				"params_schema":         "schema:example.lookup.params.v1",
				"result_schema":         "schema:example.lookup.result.v1",
				"required_capabilities": []string{"store.read"},
				"placement":             "local",
				"data_egress":           map[string]any{"network": false, "fields": []string{}},
				"suggested_limits":      map[string]any{"calls_per_hour": 10},
				"confirmation":          "grant-policy",
			},
		},
	}
	manifestJSON, err := json.Marshal(manifest)
	must(err)
	signedManifest, err := ccp.SignDocument(string(manifestJSON), seedHex)
	must(err)

	digest := "sha256:" + signedManifest.SigningInputSHA256
	signal := map[string]any{
		"ccp":          "0.5-draft",
		"request_id":   "req-go-1",
		"grant_digest": digest,
		"intent":       "example.lookup",
		"params":       map[string]any{"item_id": "item-123"},
		"issued_at":    "2026-10-22T12:00:00Z",
		"expires_at":   "2026-10-22T12:01:00Z",
	}
	signalJSON, err := json.Marshal(signal)
	must(err)
	signedSignal, err := ccp.SignDocument(string(signalJSON), seedHex)
	must(err)

	fmt.Println("manifest:", signedManifest.Wire)
	fmt.Println("manifest digest:", digest)
	fmt.Println("signal:", signedSignal.Wire)
}
