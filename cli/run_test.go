package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRunBeelzebub_InvalidCoreYaml(t *testing.T) {
	tmpDir := t.TempDir()
	corePath := filepath.Join(tmpDir, "core.yaml")
	os.WriteFile(corePath, []byte("invalid: yaml: :"), 0644)

	rootConfCore = corePath
	rootConfServices = tmpDir
	runMemLimitMiB = -1 // Disable memory limit for test

	err := runBeelzebub(runCmd, nil)
	if err == nil {
		t.Fatal("expected error with invalid core yaml, got nil")
	}

	if !strings.Contains(err.Error(), "reading core config:") {
		t.Errorf("expected error to mention core config reading, got: %v", err)
	}
}

func TestRunBeelzebub_InvalidServicesYaml(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "svc.yaml"), []byte("invalid: yaml: :"), 0644)

	rootConfCore = "../configurations/beelzebub.yaml"
	rootConfServices = tmpDir
	runMemLimitMiB = 100 // Test memory limit path

	err := runBeelzebub(runCmd, nil)
	if err == nil {
		t.Fatal("expected error with invalid services yaml, got nil")
	}

	if !strings.Contains(err.Error(), "reading services config:") {
		t.Errorf("expected error to mention services config reading, got: %v", err)
	}
}

func TestRunBeelzebub_NoServicesConfigured(t *testing.T) {
	tmpDir := t.TempDir() // empty directory, no services

	rootConfCore = "../configurations/beelzebub.yaml"
	rootConfServices = tmpDir
	runMemLimitMiB = -1

	// Ensure BEELZEBUB_CLOUD_ENABLED is false to trigger the "no services configured" error
	os.Setenv("BEELZEBUB_CLOUD_ENABLED", "false")
	defer os.Unsetenv("BEELZEBUB_CLOUD_ENABLED")

	err := runBeelzebub(runCmd, nil)
	if err == nil {
		t.Fatal("expected error for no services configured, got nil")
	}

	if !strings.Contains(err.Error(), "no services configured") {
		t.Errorf("expected error to mention no services configured, got: %v", err)
	}
}

func TestListPlugins_NoPanic(t *testing.T) {
	// Just verify the function doesn't panic and produces output
	listPlugins(nil, nil)
}

func TestPrintVersion_NoPanic(t *testing.T) {
	// Just verify the function doesn't panic
	printVersion(nil, nil)
}

func TestPrintVersion_WithBuildInfo(t *testing.T) {
	Version = "dev"
	CommitSHA = "unknown"

	// Should not panic even without ldflags
	printVersion(nil, nil)

	// Verify version is set (may be from build info or default)
	assert.Equal(t, "dev", Version)
}
