package containerruntimeconfig

// PoC tests for OCPSTRAT-3988: render ClusterImagePolicy as a signature policy
// drop-in fragment (/etc/containers/policy.json.d) instead of merging it into
// /etc/containers/policy.json and copying it into every /etc/crio/policies/<ns>.json.

import (
	"encoding/json"
	"testing"

	ign3types "github.com/coreos/ignition/v2/config/v3_5/types"
	apicfgv1 "github.com/openshift/api/config/v1"
	opv1 "github.com/openshift/api/operator/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openshift/machine-config-operator/pkg/apihelpers"
	ctrlcommon "github.com/openshift/machine-config-operator/pkg/controller/common"
	"github.com/openshift/machine-config-operator/pkg/daemon/constants"
)

func withPolicyDropIns(t *testing.T, enabled bool) {
	t.Helper()
	old := policyDropInsEnabled
	policyDropInsEnabled = enabled
	t.Cleanup(func() { policyDropInsEnabled = old })
}

type policyDoc struct {
	Default    json.RawMessage                       `json:"default"`
	Transports map[string]map[string]json.RawMessage `json:"transports"`
}

func decodePolicyDoc(t *testing.T, data []byte) policyDoc {
	t.Helper()
	var d policyDoc
	require.NoError(t, json.Unmarshal(data, &d), string(data))
	return d
}

// renderPolicyFiles runs registriesConfigIgnition and returns path -> contents.
func renderPolicyFiles(t *testing.T, allowed []string, cips []*apicfgv1.ClusterImagePolicy, ips []*apicfgv1.ImagePolicy) map[string][]byte {
	t.Helper()
	clusterScopePolicies, nsPolicies, err := getValidScopePolicies(cips, ips, nil)
	require.NoError(t, err)
	cc := newControllerConfig(ctrlcommon.ControllerConfigName, apicfgv1.AWSPlatformType)
	ign, err := registriesConfigIgnition(templateDir, cc, "worker", "release-reg.io/image/release",
		nil, nil, nil, allowed, nil, nil, nil, nil, clusterScopePolicies, nsPolicies)
	require.NoError(t, err)
	return ignitionFiles(t, ign)
}

func ignitionFiles(t *testing.T, ign *ign3types.Config) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	for _, f := range ign.Storage.Files {
		data, err := ctrlcommon.DecodeIgnitionFileContents(f.Contents.Source, f.Contents.Compression)
		require.NoError(t, err)
		files[f.Path] = data
	}
	return files
}

func testPolicies() ([]*apicfgv1.ClusterImagePolicy, []*apicfgv1.ImagePolicy) {
	key := []byte("test-key-data")
	return []*apicfgv1.ClusterImagePolicy{
		newClusterImagePolicyWithPublicKey("cip", []string{"quay.io/cip", "quay.io/a/b/c/deep"}, key),
	}, []*apicfgv1.ImagePolicy{
		newImagePolicyWithPublicKey("ip", "ns1", []string{"quay.io/ns-only"}, key),
	}
}

func TestPolicyDropInsLegacyModeUnchanged(t *testing.T) {
	withPolicyDropIns(t, false)
	cips, ips := testPolicies()
	files := renderPolicyFiles(t, nil, cips, ips)

	assert.NotContains(t, files, clusterImagePolicyFragmentPath)
	base := decodePolicyDoc(t, files[policyConfigPath])
	assert.Contains(t, base.Transports["docker"], "quay.io/cip", "legacy: CIP merged into policy.json")
	ns := decodePolicyDoc(t, files["/etc/crio/policies/ns1.json"])
	assert.Contains(t, ns.Transports["docker"], "quay.io/cip", "legacy: CIP copied into every namespace file")
}

func TestPolicyDropInsRendersClusterImagePolicyAsFragment(t *testing.T) {
	withPolicyDropIns(t, true)
	cips, ips := testPolicies()
	files := renderPolicyFiles(t, nil, cips, ips)

	frag := decodePolicyDoc(t, files[clusterImagePolicyFragmentPath])
	assert.Nil(t, frag.Default, "fragment must not set default")
	assert.Contains(t, frag.Transports["docker"], "quay.io/cip")
	assert.Contains(t, frag.Transports["docker"], "quay.io/a/b/c/deep")
	assert.Contains(t, frag.Transports["atomic"], "quay.io/cip")
	assert.NotContains(t, frag.Transports["atomic"], "quay.io/a/b/c/deep", "atomic does not support 3+ scope segments")

	base := decodePolicyDoc(t, files[policyConfigPath])
	assert.NotContains(t, base.Transports["docker"], "quay.io/cip", "policy.json no longer carries CIP scopes")

	ns := decodePolicyDoc(t, files["/etc/crio/policies/ns1.json"])
	assert.Contains(t, ns.Transports["docker"], "quay.io/ns-only")
	assert.NotContains(t, ns.Transports["docker"], "quay.io/cip", "namespace files no longer copy CIP scopes; CRI-O layers them")
	assert.Nil(t, ns.Default, "namespace layer inherits the cluster default")
	assert.NotContains(t, ns.Transports, "docker-daemon", "no copy of the cluster policy")
}

func TestPolicyDropInsNoClusterImagePolicyNoFragment(t *testing.T) {
	withPolicyDropIns(t, true)
	_, ips := testPolicies()
	files := renderPolicyFiles(t, nil, nil, ips)
	assert.NotContains(t, files, clusterImagePolicyFragmentPath, "no CIP: fragment not written, so MCD removes it from nodes")
}

func TestPolicyDropInsWithAllowedRegistries(t *testing.T) {
	withPolicyDropIns(t, true)
	cips, _ := testPolicies()
	// An allowed registry that is also a CIP scope must not get insecureAcceptAnything
	// in policy.json, else the same scope would be in two files (load error on the node).
	files := renderPolicyFiles(t, []string{"quay.io/cip", "quay.io/a", "registry.example.com"}, cips, nil)

	base := decodePolicyDoc(t, files[policyConfigPath])
	assert.JSONEq(t, `[{"type":"reject"}]`, string(base.Default))
	assert.Contains(t, base.Transports["docker"], "registry.example.com")
	assert.Contains(t, base.Transports["docker"], "quay.io/a")
	assert.NotContains(t, base.Transports["docker"], "quay.io/cip")

	frag := decodePolicyDoc(t, files[clusterImagePolicyFragmentPath])
	assert.Contains(t, frag.Transports["docker"], "quay.io/cip")
	// quay.io/a/b/c/deep (fragment) is under quay.io/a (base, insecureAcceptAnything):
	// on the node the scopes compose (AND), so the CIP signature requirement still applies.
}

func TestValidatePolicyFragmentAgainstBase(t *testing.T) {
	base := []byte(`{"default":[{"type":"insecureAcceptAnything"}],"transports":{"docker":{"quay.io/x":[{"type":"reject"}]}}}`)
	for _, tc := range []struct {
		name, fragment, wantErr string
	}{
		{"ok", `{"transports":{"docker":{"quay.io/y":[{"type":"reject"}]}}}`, ""},
		{"empty", ``, ""},
		{"duplicate scope", `{"transports":{"docker":{"quay.io/x":[{"type":"reject"}]}}}`, "defined in both"},
		{"default", `{"default":[{"type":"reject"}]}`, `"default" may only be set`},
		{"transport-wide scope", `{"transports":{"docker":{"":[{"type":"reject"}]}}}`, `"" scope may only be set`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePolicyFragmentAgainstBase("policy.json", base, "frag.json", []byte(tc.fragment))
			if tc.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.wantErr)
			}
		})
	}
}

func TestPolicyDropInDirReloadsCrio(t *testing.T) {
	path := constants.ContainerRegistryPolicyDropInDir + "/50-openshift-clusterimagepolicy.json"

	// Node disruption policy (default cluster policies).
	found, actions := ctrlcommon.FindClosestFilePolicyPathMatch(path, apihelpers.MergeClusterPolicies(opv1.NodeDisruptionPolicyConfig{}).Files)
	require.True(t, found, "policy.json.d must have a node disruption policy, else a change reboots the node")
	require.Len(t, actions, 1)
	assert.Equal(t, opv1.ReloadStatusAction, actions[0].Type)
	assert.Equal(t, opv1.NodeDisruptionPolicyServiceName("crio.service"), actions[0].Reload.ServiceName)
}
