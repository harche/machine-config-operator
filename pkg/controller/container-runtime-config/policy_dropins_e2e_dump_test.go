package containerruntimeconfig

// PoC (OCPSTRAT-3988): dump the node files MCO renders, so they can be installed
// on a CRI-O node (Lima VM) and checked with real image pulls. Skipped unless
// POC_DUMP_DIR and POC_KEY_FILE are set.
//
//	POC_DUMP_DIR=/path/out POC_KEY_FILE=keyA.pub go test ./pkg/controller/container-runtime-config/ -run TestPolicyDropInsDumpForE2E

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	apicfgv1 "github.com/openshift/api/config/v1"
	"github.com/stretchr/testify/require"
)

func TestPolicyDropInsDumpForE2E(t *testing.T) {
	out, keyFile := os.Getenv("POC_DUMP_DIR"), os.Getenv("POC_KEY_FILE")
	if out == "" || keyFile == "" {
		t.Skip("POC_DUMP_DIR and POC_KEY_FILE not set")
	}
	key, err := os.ReadFile(keyFile)
	require.NoError(t, err)

	cips := []*apicfgv1.ClusterImagePolicy{newClusterImagePolicyWithPublicKey("partner", []string{"localhost:5000/partner"}, key)}
	ips := []*apicfgv1.ImagePolicy{newImagePolicyWithPublicKey("other", "ns1", []string{"localhost:5000/other"}, key)}

	for _, sc := range []struct {
		name    string
		dropIns bool
		allowed []string
	}{
		{"legacy", false, nil},
		{"dropins", true, nil},
		{"legacy-allowed", false, []string{"localhost:5000/partner", "localhost:5000/other", "quay.io"}},
		{"dropins-allowed", true, []string{"localhost:5000/partner", "localhost:5000/other", "quay.io"}},
	} {
		t.Run(sc.name, func(t *testing.T) {
			withPolicyDropIns(t, sc.dropIns)
			files := renderPolicyFiles(t, sc.allowed, cips, ips)
			for path, data := range files {
				// Only signature-policy related files; keep the VM's registries.conf.
				if !strings.HasPrefix(path, "/etc/containers/policy.json") &&
					!strings.HasPrefix(path, "/etc/crio/policies/") &&
					!strings.HasPrefix(path, "/etc/containers/registries.d/") {
					continue
				}
				dst := filepath.Join(out, sc.name, path)
				require.NoError(t, os.MkdirAll(filepath.Dir(dst), 0o755))
				require.NoError(t, os.WriteFile(dst, data, 0o644))
			}
		})
	}
}
