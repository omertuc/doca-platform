/*
Copyright 2026 NVIDIA

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package inventory

import (
	"context"
	"testing"

	operatorv1 "github.com/nvidia/doca-platform/api/operator/v1alpha1"
	"github.com/nvidia/doca-platform/internal/release"

	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestProvisioningControllerObjects_DPUAgentServiceAccountBootstrap(t *testing.T) {
	g := NewWithT(t)
	provCtrl := provisioningControllerObjects{
		data:            provisioningControllerData,
		bfbRegistryData: bfbRegistryData,
		platformCAData:  platformCAData,
	}
	g.Expect(provCtrl.Parse()).To(Succeed())
	defaults := &release.Defaults{}
	g.Expect(defaults.Parse()).To(Succeed())

	newVars := func(saNamespace string) Variables {
		vars := newDefaultVariables(defaults)
		vars.Namespace = "dpf-operator-system"
		vars.DPFProvisioningController = DPFProvisioningVariables{
			BFBPersistentVolumeClaimName:    ptr.To(TestPVC),
			DeploymentMode:                  operatorv1.DeploymentModeZeroTrust,
			DPUAgentServiceAccountNamespace: saNamespace,
		}
		return vars
	}
	find := func(objs []client.Object, kind ObjectKind, namespace, name string) client.Object {
		for _, obj := range objs {
			if obj.GetObjectKind().GroupVersionKind().Kind == string(kind) && obj.GetNamespace() == namespace && obj.GetName() == name {
				return obj
			}
		}
		return nil
	}

	t.Run("renders nothing for the BootstrapToken method", func(t *testing.T) {
		g := NewWithT(t)
		objs, err := provCtrl.GenerateManifests(context.Background(), newVars(""))
		g.Expect(err).NotTo(HaveOccurred())
		for _, obj := range objs {
			g.Expect(obj.GetObjectKind().GroupVersionKind().Kind).NotTo(Equal(string(NamespaceKind)))
			g.Expect(obj.GetName()).NotTo(Equal(dpuAgentServiceAccountBootstrapName))
		}
	})

	t.Run("renders the namespace and RBAC for the ServiceAccountToken method", func(t *testing.T) {
		g := NewWithT(t)
		vars := newVars("dpu-agent-bootstrap")
		objs, err := provCtrl.GenerateManifests(context.Background(), vars)
		g.Expect(err).NotTo(HaveOccurred())

		ns := find(objs, NamespaceKind, "", "dpu-agent-bootstrap")
		g.Expect(ns).NotTo(BeNil())
		g.Expect(ns.GetLabels()).To(HaveKeyWithValue(applysetPartOfLabel, ApplySetID(vars.Namespace, &provCtrl)))
		g.Expect(ns.GetLabels()).To(HaveKeyWithValue("pod-security.kubernetes.io/enforce", "restricted"))

		// Granting every ServiceAccount in the namespace the DPU Agent CSR creator role.
		binding, ok := find(objs, ClusterRoleBindingKind, "", dpuAgentServiceAccountBootstrapName).(*rbacv1.ClusterRoleBinding)
		g.Expect(ok).To(BeTrue())
		g.Expect(binding.Subjects).To(ConsistOf(rbacv1.Subject{
			APIGroup: rbacv1.GroupName,
			Kind:     rbacv1.GroupKind,
			Name:     "system:serviceaccounts:dpu-agent-bootstrap",
		}))
		g.Expect(binding.RoleRef.Name).To(Equal(dpuAgentCSRCreatorClusterRoleName))
		g.Expect(find(objs, ClusterRoleKind, "", dpuAgentCSRCreatorClusterRoleName)).NotTo(BeNil(),
			"the bound ClusterRole must be one the provisioning manifests ship")

		// Letting the provisioning controller manage the ServiceAccounts in that namespace only.
		role, ok := find(objs, RoleKind, "dpu-agent-bootstrap", dpuAgentServiceAccountBootstrapName).(*rbacv1.Role)
		g.Expect(ok).To(BeTrue())
		g.Expect(role.Rules).To(ContainElement(rbacv1.PolicyRule{
			APIGroups: []string{""},
			Resources: []string{"serviceaccounts/token"},
			Verbs:     []string{"create"},
		}))
		roleBinding, ok := find(objs, RoleBindingKind, "dpu-agent-bootstrap", dpuAgentServiceAccountBootstrapName).(*rbacv1.RoleBinding)
		g.Expect(ok).To(BeTrue())
		g.Expect(roleBinding.RoleRef.Name).To(Equal(role.Name))
		g.Expect(roleBinding.Subjects).To(ConsistOf(rbacv1.Subject{
			Kind:      rbacv1.ServiceAccountKind,
			Name:      DPFProvisioningControllerName,
			Namespace: vars.Namespace,
		}))
		g.Expect(find(objs, ServiceAccountKind, vars.Namespace, DPFProvisioningControllerName)).NotTo(BeNil(),
			"the bound ServiceAccount must be the one the provisioning controller runs as")

		// Applying the namespace before the objects in it.
		nsIndex, roleIndex := -1, -1
		for i, obj := range objs {
			switch obj {
			case ns:
				nsIndex = i
			case client.Object(role):
				roleIndex = i
			}
		}
		g.Expect(nsIndex).To(BeNumerically("<", roleIndex))
	})
}

func TestSetBasicConfig_DPUAgentServiceAccountNamespace(t *testing.T) {
	newConfig := func(security *operatorv1.SecurityConfiguration) *operatorv1.DPFOperatorConfig {
		return &operatorv1.DPFOperatorConfig{Spec: operatorv1.DPFOperatorConfigSpec{
			ProvisioningController: &operatorv1.ProvisioningControllerConfiguration{},
			Security:               security,
		}}
	}
	tests := []struct {
		name     string
		security *operatorv1.SecurityConfiguration
		want     string
	}{
		{name: "unset", want: ""},
		{name: "BootstrapToken", security: &operatorv1.SecurityConfiguration{DPUAgentBootstrap: &operatorv1.DPUAgentBootstrapConfiguration{
			Method:                  operatorv1.DPUAgentBootstrapMethodBootstrapToken,
			ServiceAccountNamespace: "dpu-agent-bootstrap",
		}}, want: ""},
		{name: "ServiceAccountToken in the default namespace", security: &operatorv1.SecurityConfiguration{DPUAgentBootstrap: &operatorv1.DPUAgentBootstrapConfiguration{
			Method: operatorv1.DPUAgentBootstrapMethodServiceAccountToken,
		}}, want: operatorv1.DefaultDPUAgentBootstrapServiceAccountNamespace},
		{name: "ServiceAccountToken in a namespace of its own", security: &operatorv1.SecurityConfiguration{DPUAgentBootstrap: &operatorv1.DPUAgentBootstrapConfiguration{
			Method:                  operatorv1.DPUAgentBootstrapMethodServiceAccountToken,
			ServiceAccountNamespace: "dpu-agent-bootstrap",
		}}, want: "dpu-agent-bootstrap"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vars := setBasicConfig(Variables{}, newConfig(tt.security))
			if got := vars.DPFProvisioningController.DPUAgentServiceAccountNamespace; got != tt.want {
				t.Errorf("DPUAgentServiceAccountNamespace = %q, want %q", got, tt.want)
			}
		})
	}
}
