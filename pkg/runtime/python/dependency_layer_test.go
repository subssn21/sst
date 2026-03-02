package python

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/sst/sst/v3/pkg/runtime"
)

// TestComputeLayerFingerprint validates fingerprint determinism and input sensitivity.
// **Validates: Requirements 4.1, 4.2, 8.2**
func TestComputeLayerFingerprint(t *testing.T) {
	baseReqHash := "abc123def456"
	baseRuntime := "python3.13"
	baseArch := "x86_64"
	baseWsHash := "ws-source-hash-abc"
	baseFingerprint := computeLayerFingerprint(baseReqHash, baseRuntime, baseArch, baseWsHash)

	t.Run("determinism: same inputs produce same hash", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			got := computeLayerFingerprint(baseReqHash, baseRuntime, baseArch, baseWsHash)
			if got != baseFingerprint {
				t.Fatalf("call %d: got %s, want %s", i, got, baseFingerprint)
			}
		}
	})

	t.Run("different requirementsHash produces different hash", func(t *testing.T) {
		got := computeLayerFingerprint("different-hash", baseRuntime, baseArch, baseWsHash)
		if got == baseFingerprint {
			t.Fatal("expected different fingerprint when requirementsHash differs")
		}
	})

	t.Run("different runtimeVersion produces different hash", func(t *testing.T) {
		got := computeLayerFingerprint(baseReqHash, "python3.12", baseArch, baseWsHash)
		if got == baseFingerprint {
			t.Fatal("expected different fingerprint when runtimeVersion differs")
		}
	})

	t.Run("different architecture produces different hash", func(t *testing.T) {
		got := computeLayerFingerprint(baseReqHash, baseRuntime, "arm64", baseWsHash)
		if got == baseFingerprint {
			t.Fatal("expected different fingerprint when architecture differs")
		}
	})

	t.Run("different workspaceSourceHash produces different hash", func(t *testing.T) {
		got := computeLayerFingerprint(baseReqHash, baseRuntime, baseArch, "different-ws-hash")
		if got == baseFingerprint {
			t.Fatal("expected different fingerprint when workspaceSourceHash differs")
		}
	})

	t.Run("empty requirements hash produces valid non-empty hash", func(t *testing.T) {
		got := computeLayerFingerprint("", baseRuntime, baseArch, baseWsHash)
		if got == "" {
			t.Fatal("expected non-empty fingerprint for empty requirements hash")
		}
		if len(got) != 64 {
			t.Fatalf("expected 64-char hex SHA-256, got %d chars: %s", len(got), got)
		}
	})
}

// TestDependencyLayerBuild validates that building a Python function with dependencyLayer: true
// produces the correct output structure: a layer directory with the Lambda-compatible
// python/lib/pythonX.Y/site-packages/ layout, and a function artifact that excludes
// third-party dependencies.
//
// **Property 4: Artifact excludes dependencies when dependencyLayer is enabled**
// **Property 5: Layer directory structure and completeness**
// **Validates: Requirements 3.1, 3.2, 3.3, 6.3**
func TestDependencyLayerBuild(t *testing.T) {
	// Skip if uv is not available
	if _, err := exec.LookPath("uv"); err != nil {
		t.Skip("uv not found in PATH, skipping integration test")
	}

	// Find project root
	projectRoot, err := findProjectRoot()
	if err != nil {
		t.Skipf("Could not find project root: %v", err)
	}

	examplePath := filepath.Join(projectRoot, "examples", "python-layouts", "flat-layout")
	if _, err := os.Stat(examplePath); os.IsNotExist(err) {
		t.Skipf("flat-layout example not found at %s, skipping", examplePath)
	}

	// Ensure uv.lock exists (required for dependency resolution)
	if _, err := os.Stat(filepath.Join(examplePath, "uv.lock")); os.IsNotExist(err) {
		t.Skipf("uv.lock not found in flat-layout example, skipping")
	}

	pythonRuntime := New()
	functionID := "dep-layer-test-flat"
	runtimeVersion := "python3.11"

	// Build with dependencyLayer: true
	properties := json.RawMessage(`{"architecture": "x86_64", "container": false, "dependencyLayer": true}`)

	result, err := pythonRuntime.Build(context.Background(), &runtime.BuildInput{
		FunctionID: functionID,
		Handler:    "handler.main",
		Runtime:    runtimeVersion,
		Properties: properties,
		CfgPath:    filepath.Join(examplePath, "sst.config.ts"),
	})
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// --- Property 5: Layer directory structure and completeness ---

	t.Run("BuildOutput.Layers has one entry", func(t *testing.T) {
		if len(result.Layers) != 1 {
			t.Fatalf("expected 1 layer in BuildOutput.Layers, got %d", len(result.Layers))
		}
	})

	t.Run("layer has non-empty hash and description", func(t *testing.T) {
		layer := result.Layers[0]
		if layer.Hash == "" {
			t.Fatal("expected non-empty Hash on LayerOutput")
		}
		if layer.Description == "" {
			t.Fatal("expected non-empty Description on LayerOutput")
		}
		if layer.Dir == "" {
			t.Fatal("expected non-empty Dir on LayerOutput")
		}
	})

	t.Run("layer dir contains python/lib/pythonX.Y/site-packages/ structure", func(t *testing.T) {
		layer := result.Layers[0]
		sitePackagesPath := filepath.Join(layer.Dir, "python", "lib", runtimeVersion, "site-packages")
		info, err := os.Stat(sitePackagesPath)
		if err != nil {
			t.Fatalf("expected site-packages directory at %s, got error: %v", sitePackagesPath, err)
		}
		if !info.IsDir() {
			t.Fatalf("expected %s to be a directory", sitePackagesPath)
		}
	})

	t.Run("layer site-packages contains third-party dependencies", func(t *testing.T) {
		layer := result.Layers[0]
		sitePackagesPath := filepath.Join(layer.Dir, "python", "lib", runtimeVersion, "site-packages")

		// The flat-layout example depends on "requests" — verify it's in the layer
		requestsFound := false
		entries, err := os.ReadDir(sitePackagesPath)
		if err != nil {
			t.Fatalf("failed to read site-packages dir: %v", err)
		}
		for _, entry := range entries {
			if entry.Name() == "requests" && entry.IsDir() {
				requestsFound = true
				break
			}
		}
		if !requestsFound {
			names := make([]string, 0, len(entries))
			for _, e := range entries {
				names = append(names, e.Name())
			}
			t.Fatalf("expected 'requests' package in layer site-packages, found: %v", names)
		}
	})

	// --- Property 4: Artifact excludes dependencies when dependencyLayer is enabled ---

	t.Run("function artifact does NOT contain third-party packages", func(t *testing.T) {
		artifactDir := result.Out

		// Walk the artifact directory and check that no third-party packages are present.
		// "requests" and "urllib3" (a transitive dep of requests) should NOT be in the artifact.
		thirdPartyPackages := []string{"requests", "urllib3", "charset_normalizer", "certifi", "idna"}
		for _, pkg := range thirdPartyPackages {
			pkgPath := filepath.Join(artifactDir, pkg)
			if _, err := os.Stat(pkgPath); err == nil {
				t.Errorf("third-party package %q should NOT be in artifact dir %s", pkg, artifactDir)
			}
		}
	})

	t.Run("function artifact contains source code", func(t *testing.T) {
		artifactDir := result.Out

		// The flat-layout example has handler.py — it should be in the artifact
		hasPythonSource := false
		err := filepath.Walk(artifactDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if filepath.Ext(path) == ".py" {
				hasPythonSource = true
			}
			return nil
		})
		if err != nil {
			t.Fatalf("error walking artifact dir: %v", err)
		}
		if !hasPythonSource {
			t.Fatal("expected at least one .py file in the function artifact directory")
		}
	})
}

// TestDependencyLayerCacheReuse validates that two functions with the same dependencies
// and dependencyLayer: true produce the same LayerOutput.Hash and reuse the same
// .layers/ cache directory (no duplication).
//
// **Property 7: One LayerVersion per unique hash**
// **Validates: Requirements 4.3, 6.1, 6.2**
func TestDependencyLayerCacheReuse(t *testing.T) {
	// Skip if uv is not available
	if _, err := exec.LookPath("uv"); err != nil {
		t.Skip("uv not found in PATH, skipping integration test")
	}

	// Find project root
	projectRoot, err := findProjectRoot()
	if err != nil {
		t.Skipf("Could not find project root: %v", err)
	}

	examplePath := filepath.Join(projectRoot, "examples", "python-layouts", "flat-layout")
	if _, err := os.Stat(examplePath); os.IsNotExist(err) {
		t.Skipf("flat-layout example not found at %s, skipping", examplePath)
	}

	if _, err := os.Stat(filepath.Join(examplePath, "uv.lock")); os.IsNotExist(err) {
		t.Skipf("uv.lock not found in flat-layout example, skipping")
	}

	pythonRuntime := New()
	runtimeVersion := "python3.11"
	properties := json.RawMessage(`{"architecture": "x86_64", "container": false, "dependencyLayer": true}`)

	// Build first function
	result1, err := pythonRuntime.Build(context.Background(), &runtime.BuildInput{
		FunctionID: "cache-reuse-func-a",
		Handler:    "handler.main",
		Runtime:    runtimeVersion,
		Properties: properties,
		CfgPath:    filepath.Join(examplePath, "sst.config.ts"),
	})
	if err != nil {
		t.Fatalf("Build 1 failed: %v", err)
	}

	// Build second function with a different ID but same deps
	result2, err := pythonRuntime.Build(context.Background(), &runtime.BuildInput{
		FunctionID: "cache-reuse-func-b",
		Handler:    "handler.main",
		Runtime:    runtimeVersion,
		Properties: properties,
		CfgPath:    filepath.Join(examplePath, "sst.config.ts"),
	})
	if err != nil {
		t.Fatalf("Build 2 failed: %v", err)
	}

	// Both builds must produce exactly one layer
	if len(result1.Layers) != 1 {
		t.Fatalf("expected 1 layer from build 1, got %d", len(result1.Layers))
	}
	if len(result2.Layers) != 1 {
		t.Fatalf("expected 1 layer from build 2, got %d", len(result2.Layers))
	}

	layer1 := result1.Layers[0]
	layer2 := result2.Layers[0]

	t.Run("both builds produce the same LayerOutput.Hash", func(t *testing.T) {
		if layer1.Hash != layer2.Hash {
			t.Fatalf("expected identical hashes, got %q and %q", layer1.Hash, layer2.Hash)
		}
	})

	t.Run("both builds point to the same layer directory (cache reuse)", func(t *testing.T) {
		if layer1.Dir != layer2.Dir {
			t.Fatalf("expected same layer Dir (cache reuse), got:\n  build1: %s\n  build2: %s", layer1.Dir, layer2.Dir)
		}
	})

	t.Run("layer directory exists and contains site-packages", func(t *testing.T) {
		sitePackagesPath := filepath.Join(layer1.Dir, "python", "lib", runtimeVersion, "site-packages")
		info, err := os.Stat(sitePackagesPath)
		if err != nil {
			t.Fatalf("expected site-packages at %s, got error: %v", sitePackagesPath, err)
		}
		if !info.IsDir() {
			t.Fatalf("expected %s to be a directory", sitePackagesPath)
		}
	})

	t.Run("function artifacts are in different directories", func(t *testing.T) {
		if result1.Out == result2.Out {
			t.Fatal("expected different artifact directories for different function IDs")
		}
	})
}

// TestDependencyLayerDevMode validates that building with Dev: true and dependencyLayer: true
// produces no layers in the output — dev mode ignores the dependencyLayer option.
//
// **Property 2: dependencyLayer ignored in dev and container modes**
// **Validates: Requirements 2.5**
func TestDependencyLayerDevMode(t *testing.T) {
	// Skip if uv is not available
	if _, err := exec.LookPath("uv"); err != nil {
		t.Skip("uv not found in PATH, skipping integration test")
	}

	// Find project root
	projectRoot, err := findProjectRoot()
	if err != nil {
		t.Skipf("Could not find project root: %v", err)
	}

	examplePath := filepath.Join(projectRoot, "examples", "python-layouts", "flat-layout")
	if _, err := os.Stat(examplePath); os.IsNotExist(err) {
		t.Skipf("flat-layout example not found at %s, skipping", examplePath)
	}

	if _, err := os.Stat(filepath.Join(examplePath, "uv.lock")); os.IsNotExist(err) {
		t.Skipf("uv.lock not found in flat-layout example, skipping")
	}

	pythonRuntime := New()
	runtimeVersion := "python3.11"
	properties := json.RawMessage(`{"architecture": "x86_64", "container": false, "dependencyLayer": true}`)

	// Build with Dev: true AND dependencyLayer: true in properties
	result, err := pythonRuntime.Build(context.Background(), &runtime.BuildInput{
		Dev:        true,
		FunctionID: "dev-mode-layer-test",
		Handler:    "handler.main",
		Runtime:    runtimeVersion,
		Properties: properties,
		CfgPath:    filepath.Join(examplePath, "sst.config.ts"),
	})
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	t.Run("BuildOutput.Layers is nil or empty in dev mode", func(t *testing.T) {
		if len(result.Layers) != 0 {
			t.Fatalf("expected no layers in dev mode, got %d layers", len(result.Layers))
		}
	})
}

// TestDependencyLayerArchitectureSeparation validates that building the same function
// with different architectures (x86_64 vs arm64) and dependencyLayer: true produces
// different LayerOutput.Hash and LayerOutput.Dir values, ensuring architecture-specific
// layers are kept separate.
//
// **Property 6: Fingerprint determinism and input sensitivity**
// **Validates: Requirements 8.2, 8.3**
func TestDependencyLayerArchitectureSeparation(t *testing.T) {
	// Skip if uv is not available
	if _, err := exec.LookPath("uv"); err != nil {
		t.Skip("uv not found in PATH, skipping integration test")
	}

	// Find project root
	projectRoot, err := findProjectRoot()
	if err != nil {
		t.Skipf("Could not find project root: %v", err)
	}

	examplePath := filepath.Join(projectRoot, "examples", "python-layouts", "flat-layout")
	if _, err := os.Stat(examplePath); os.IsNotExist(err) {
		t.Skipf("flat-layout example not found at %s, skipping", examplePath)
	}

	if _, err := os.Stat(filepath.Join(examplePath, "uv.lock")); os.IsNotExist(err) {
		t.Skipf("uv.lock not found in flat-layout example, skipping")
	}

	pythonRuntime := New()
	runtimeVersion := "python3.11"

	// Build with x86_64 architecture
	propsX86 := json.RawMessage(`{"architecture": "x86_64", "container": false, "dependencyLayer": true}`)
	resultX86, err := pythonRuntime.Build(context.Background(), &runtime.BuildInput{
		FunctionID: "arch-test-x86",
		Handler:    "handler.main",
		Runtime:    runtimeVersion,
		Properties: propsX86,
		CfgPath:    filepath.Join(examplePath, "sst.config.ts"),
	})
	if err != nil {
		t.Fatalf("Build (x86_64) failed: %v", err)
	}

	// Build with arm64 architecture
	propsArm := json.RawMessage(`{"architecture": "arm64", "container": false, "dependencyLayer": true}`)
	resultArm, err := pythonRuntime.Build(context.Background(), &runtime.BuildInput{
		FunctionID: "arch-test-arm64",
		Handler:    "handler.main",
		Runtime:    runtimeVersion,
		Properties: propsArm,
		CfgPath:    filepath.Join(examplePath, "sst.config.ts"),
	})
	if err != nil {
		t.Fatalf("Build (arm64) failed: %v", err)
	}

	// Both builds must produce exactly one layer
	if len(resultX86.Layers) != 1 {
		t.Fatalf("expected 1 layer from x86_64 build, got %d", len(resultX86.Layers))
	}
	if len(resultArm.Layers) != 1 {
		t.Fatalf("expected 1 layer from arm64 build, got %d", len(resultArm.Layers))
	}

	layerX86 := resultX86.Layers[0]
	layerArm := resultArm.Layers[0]

	t.Run("different architectures produce different LayerOutput.Hash", func(t *testing.T) {
		if layerX86.Hash == layerArm.Hash {
			t.Fatalf("expected different hashes for x86_64 vs arm64, both got %q", layerX86.Hash)
		}
	})

	t.Run("different architectures produce different LayerOutput.Dir", func(t *testing.T) {
		if layerX86.Dir == layerArm.Dir {
			t.Fatalf("expected different layer directories for x86_64 vs arm64, both got %q", layerX86.Dir)
		}
	})
}
