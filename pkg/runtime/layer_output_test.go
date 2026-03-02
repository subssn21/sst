package runtime

import (
	"encoding/json"
	"testing"
)

// TestBuildOutputJSONSerializationRoundTrip validates Property 1: BuildOutput serialization round-trip.
// For any valid BuildOutput containing zero or more LayerOutput entries, serializing to JSON and
// deserializing back should produce an equivalent BuildOutput with all Layers fields preserved.
// Validates: Requirements 1.1, 1.2
func TestBuildOutputJSONSerializationRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		input BuildOutput
		// expectLayersInJSON controls whether we expect "layers" key in the JSON output
		expectLayersInJSON bool
	}{
		{
			name: "nil layers omitted from JSON",
			input: BuildOutput{
				Out:        "/tmp/artifacts/fn1-src",
				Handler:    "handler.handler",
				Errors:     []string{},
				Sourcemaps: []string{},
				Layers:     nil,
			},
			expectLayersInJSON: false,
		},
		{
			name: "empty layers omitted from JSON",
			input: BuildOutput{
				Out:        "/tmp/artifacts/fn2-src",
				Handler:    "index.handler",
				Errors:     []string{},
				Sourcemaps: []string{},
				Layers:     []LayerOutput{},
			},
			expectLayersInJSON: false,
		},
		{
			name: "single layer round-trips correctly",
			input: BuildOutput{
				Out:        "/tmp/artifacts/fn3-src",
				Handler:    "app.handler",
				Errors:     []string{},
				Sourcemaps: []string{},
				Layers: []LayerOutput{
					{
						Dir:         "/tmp/.layers/abc123-x86_64",
						Hash:        "abc123def456",
						Description: "python3.13-x86_64 dependencies",
					},
				},
			},
			expectLayersInJSON: true,
		},
		{
			name: "multiple layers round-trip correctly",
			input: BuildOutput{
				Out:        "/tmp/artifacts/fn4-src",
				Handler:    "main.handler",
				Errors:     []string{"warning1"},
				Sourcemaps: []string{"main.js.map"},
				Layers: []LayerOutput{
					{
						Dir:         "/tmp/.layers/aaa-x86_64",
						Hash:        "hash_aaa",
						Description: "python3.13-x86_64 dependencies",
					},
					{
						Dir:         "/tmp/.layers/bbb-arm64",
						Hash:        "hash_bbb",
						Description: "python3.13-arm64 native extensions",
					},
				},
			},
			expectLayersInJSON: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Serialize to JSON
			data, err := json.Marshal(tc.input)
			if err != nil {
				t.Fatalf("failed to marshal BuildOutput: %v", err)
			}

			// Check whether "layers" key is present in JSON
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(data, &raw); err != nil {
				t.Fatalf("failed to unmarshal into raw map: %v", err)
			}
			_, hasLayers := raw["layers"]
			if tc.expectLayersInJSON && !hasLayers {
				t.Errorf("expected 'layers' key in JSON but it was absent")
			}
			if !tc.expectLayersInJSON && hasLayers {
				t.Errorf("expected 'layers' key to be omitted from JSON but it was present")
			}

			// Deserialize back
			var got BuildOutput
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("failed to unmarshal BuildOutput: %v", err)
			}

			// Verify round-trip: all scalar fields match
			if got.Out != tc.input.Out {
				t.Errorf("Out: got %q, want %q", got.Out, tc.input.Out)
			}
			if got.Handler != tc.input.Handler {
				t.Errorf("Handler: got %q, want %q", got.Handler, tc.input.Handler)
			}

			// Verify Layers round-trip
			if len(got.Layers) != len(tc.input.Layers) {
				t.Fatalf("Layers length: got %d, want %d", len(got.Layers), len(tc.input.Layers))
			}
			for i, wantLayer := range tc.input.Layers {
				gotLayer := got.Layers[i]
				if gotLayer.Dir != wantLayer.Dir {
					t.Errorf("Layers[%d].Dir: got %q, want %q", i, gotLayer.Dir, wantLayer.Dir)
				}
				if gotLayer.Hash != wantLayer.Hash {
					t.Errorf("Layers[%d].Hash: got %q, want %q", i, gotLayer.Hash, wantLayer.Hash)
				}
				if gotLayer.Description != wantLayer.Description {
					t.Errorf("Layers[%d].Description: got %q, want %q", i, gotLayer.Description, wantLayer.Description)
				}
			}
		})
	}
}
