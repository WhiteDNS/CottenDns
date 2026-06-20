// ==============================================================================
// CottenpickDNS
// Author: tajirax
// Github: https://github.com/TaJirax/cottenpickDNS
// Year: 2026
// ==============================================================================
// shipped_templates_test.go — guards the config templates that the one-line
// installers deploy verbatim (server_config.toml.simple / client_config.toml.simple).
// They must parse cleanly through the real loaders and expose the newer feature
// knobs, so a fresh install always carries them.
// ==============================================================================

package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func repoFile(name string) string {
	// This test file lives in internal/config; the templates are two levels up.
	return filepath.Join("..", "..", name)
}

func TestShippedServerTemplateParsesWithFeatureKnobs(t *testing.T) {
	cfg, err := LoadServerConfig(repoFile("server_config.toml.simple"))
	if err != nil {
		t.Fatalf("server_config.toml.simple failed to load: %v", err)
	}
	// Auto-detect and the FEC defaults must be present and sane so a fresh
	// deploy honors whatever delivery/encryption method the client picks.
	if !cfg.EncryptionAutoDetect {
		t.Errorf("ENCRYPTION_AUTO_DETECT should default true in the shipped template")
	}
	if cfg.FECBlockSize <= 0 || cfg.FECParity <= 0 {
		t.Errorf("FEC defaults not finalized: block=%d parity=%d", cfg.FECBlockSize, cfg.FECParity)
	}
	if cfg.FECBlockSize+cfg.FECParity > 256 {
		t.Errorf("FEC shard total exceeds 256: block=%d parity=%d", cfg.FECBlockSize, cfg.FECParity)
	}
}

func TestShippedClientTemplateParses(t *testing.T) {
	// The shipped client template has a placeholder ENCRYPTION_KEY the user
	// fills in (it comes from the server), so a standalone load is expected to
	// fail at exactly that validation — and nowhere earlier. Reaching the
	// key-required check proves the TOML and QUERY_TYPES (incl. the new NULL /
	// HTTPS / SVCB names) are structurally valid.
	_, err := LoadClientConfig(repoFile("client_config.toml.simple"))
	if err == nil {
		return // a key was present; fully valid.
	}
	if !strings.Contains(err.Error(), "ENCRYPTION_KEY") {
		t.Fatalf("client_config.toml.simple failed before the key check (template is malformed): %v", err)
	}
}
