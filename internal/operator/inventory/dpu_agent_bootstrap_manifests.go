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
	"maps"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// dpuAgentCSRCreatorClusterRoleName is the ClusterRole, shipped in the provisioning controller
	// manifests, that lets the DPU Agent request its client certificate.
	dpuAgentCSRCreatorClusterRoleName = "dpf-provisioning-dpu-agent-csr-creator"
	// dpuAgentServiceAccountBootstrapName names the objects that let the DPU Agent bootstrap with a
	// ServiceAccount token.
	dpuAgentServiceAccountBootstrapName = "dpf-provisioning-dpu-agent-sa-bootstrap"
)

// dpuAgentServiceAccountBootstrapObjects returns the objects of the ServiceAccountToken DPU Agent
// bootstrap method, which depend on the namespace the DPFOperatorConfig dedicates to the per-DPU
// ServiceAccounts, and so are rendered here rather than shipped in the provisioning manifests:
//
//   - the namespace;
//   - a ClusterRoleBinding letting every ServiceAccount in it request a DPU Agent client
//     certificate, the counterpart of the binding of the bootstrap token group. That the namespace
//     holds nothing but these ServiceAccounts is what keeps this grant to DPU Agents;
//   - a Role and RoleBinding letting the provisioning controller manage the ServiceAccounts and
//     mint their tokens in that namespace only, rather than for every ServiceAccount of the cluster.
//
// It returns nothing unless the ServiceAccountToken method is selected.
func dpuAgentServiceAccountBootstrapObjects(vars Variables, labels map[string]string) []client.Object {
	namespace := vars.DPFProvisioningController.DPUAgentServiceAccountNamespace
	if namespace == "" {
		return nil
	}

	namespaceLabels := maps.Clone(labels)
	// Nothing runs in the namespace.
	namespaceLabels["pod-security.kubernetes.io/enforce"] = "restricted"
	ns := &corev1.Namespace{
		TypeMeta:   metav1.TypeMeta{APIVersion: corev1.SchemeGroupVersion.String(), Kind: string(NamespaceKind)},
		ObjectMeta: metav1.ObjectMeta{Name: namespace, Labels: namespaceLabels},
	}

	csrCreatorBinding := &rbacv1.ClusterRoleBinding{
		TypeMeta:   metav1.TypeMeta{APIVersion: rbacv1.SchemeGroupVersion.String(), Kind: string(ClusterRoleBindingKind)},
		ObjectMeta: metav1.ObjectMeta{Name: dpuAgentServiceAccountBootstrapName, Labels: maps.Clone(labels)},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     string(ClusterRoleKind),
			Name:     dpuAgentCSRCreatorClusterRoleName,
		},
		Subjects: []rbacv1.Subject{{
			APIGroup: rbacv1.GroupName,
			Kind:     rbacv1.GroupKind,
			Name:     serviceaccount.MakeNamespaceGroupName(namespace),
		}},
	}

	controllerRole := &rbacv1.Role{
		TypeMeta:   metav1.TypeMeta{APIVersion: rbacv1.SchemeGroupVersion.String(), Kind: string(RoleKind)},
		ObjectMeta: metav1.ObjectMeta{Name: dpuAgentServiceAccountBootstrapName, Namespace: namespace, Labels: maps.Clone(labels)},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts"},
				Verbs:     []string{"get", "list", "create", "patch", "delete"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts/token"},
				Verbs:     []string{"create"},
			},
		},
	}
	controllerRoleBinding := &rbacv1.RoleBinding{
		TypeMeta:   metav1.TypeMeta{APIVersion: rbacv1.SchemeGroupVersion.String(), Kind: string(RoleBindingKind)},
		ObjectMeta: metav1.ObjectMeta{Name: dpuAgentServiceAccountBootstrapName, Namespace: namespace, Labels: maps.Clone(labels)},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     string(RoleKind),
			Name:     controllerRole.Name,
		},
		Subjects: []rbacv1.Subject{{
			Kind:      rbacv1.ServiceAccountKind,
			Name:      DPFProvisioningControllerName,
			Namespace: vars.Namespace,
		}},
	}

	// The namespace comes first: the objects are applied in order, and the Role and RoleBinding
	// live in it.
	return []client.Object{ns, csrCreatorBinding, controllerRole, controllerRoleBinding}
}
