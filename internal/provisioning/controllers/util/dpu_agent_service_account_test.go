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

package util

import (
	"context"
	"strings"
	"time"

	operatorv1 "github.com/nvidia/doca-platform/api/operator/v1alpha1"
	provisioningv1 "github.com/nvidia/doca-platform/api/provisioning/v1alpha1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

var _ = Describe("DPU agent bootstrap ServiceAccounts", func() {
	const saNamespace = "dpu-agent-bootstrap-test"

	var (
		ctx    context.Context
		scheme *runtime.Scheme
		dpu    *provisioningv1.DPU
	)

	BeforeEach(func() {
		ctx = context.Background()
		scheme = newTestScheme()
		Expect(operatorv1.AddToScheme(scheme)).To(Succeed())
		dpu = newTestDPU("dpu-01", "dpf-operator-system")
		dpu.Status.IdentityMode = ptr.To(provisioningv1.IdentityModeServiceAccountToken)
	})

	newServiceAccount := func(name, dpuName string) *corev1.ServiceAccount {
		return &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: saNamespace,
			Labels: map[string]string{
				LabelDPUName:      dpuName,
				LabelDPUNamespace: "dpf-operator-system",
			},
		}}
	}

	listServiceAccounts := func(c client.Client, namespace string) []string {
		saList := &corev1.ServiceAccountList{}
		Expect(c.List(ctx, saList, client.InNamespace(namespace))).To(Succeed())
		names := make([]string, 0, len(saList.Items))
		for _, sa := range saList.Items {
			names = append(names, sa.Name)
		}
		return names
	}

	Describe("DPUAgentServiceAccountName", func() {
		It("is derived from the DPU UID, not its name", func() {
			long := newTestDPU(strings.Repeat("a", 253), "other-namespace")
			Expect(DPUAgentServiceAccountName(long)).To(Equal("dpu-agent-test-uid-12345"))
			Expect(DPUAgentServiceAccountName(dpu)).To(Equal(DPUAgentServiceAccountName(long)))
		})
	})

	Describe("CreateDPUAgentServiceAccountToken", func() {
		It("creates the labeled ServiceAccount and returns a token of it", func() {
			var tokenRequest *authenticationv1.TokenRequest
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
				SubResourceCreate: func(ctx context.Context, c client.Client, subResourceName string, obj client.Object, subResource client.Object, opts ...client.SubResourceCreateOption) error {
					tokenRequest = subResource.(*authenticationv1.TokenRequest).DeepCopy()
					return c.SubResource(subResourceName).Create(ctx, obj, subResource, opts...)
				},
			}).Build()

			token, err := CreateDPUAgentServiceAccountToken(ctx, fakeClient, dpu, saNamespace)
			Expect(err).NotTo(HaveOccurred())
			Expect(token).To(Equal("fake-token"))

			sa := &corev1.ServiceAccount{}
			Expect(fakeClient.Get(ctx, client.ObjectKey{Namespace: saNamespace, Name: "dpu-agent-test-uid-12345"}, sa)).To(Succeed())
			Expect(sa.Labels).To(Equal(map[string]string{
				LabelDPUName:      "dpu-01",
				LabelDPUNamespace: "dpf-operator-system",
				LabelDPUUID:       "test-uid-12345",
			}))
			Expect(sa.AutomountServiceAccountToken).To(Equal(ptr.To(false)))

			By("requesting the bootstrap token lifetime and the API server's default audience")
			Expect(tokenRequest).NotTo(BeNil())
			Expect(tokenRequest.Spec.ExpirationSeconds).To(Equal(ptr.To(int64((4 * time.Hour).Seconds()))))
			Expect(tokenRequest.Spec.Audiences).To(BeEmpty())
			Expect(tokenRequest.Spec.BoundObjectRef).To(BeNil())
		})

		It("reuses the ServiceAccount and restores its labels", func() {
			existing := newServiceAccount("dpu-agent-test-uid-12345", "tampered")
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build()

			_, err := CreateDPUAgentServiceAccountToken(ctx, fakeClient, dpu, saNamespace)
			Expect(err).NotTo(HaveOccurred())
			_, err = CreateDPUAgentServiceAccountToken(ctx, fakeClient, dpu, saNamespace)
			Expect(err).NotTo(HaveOccurred())

			Expect(listServiceAccounts(fakeClient, saNamespace)).To(ConsistOf("dpu-agent-test-uid-12345"))
			sa := &corev1.ServiceAccount{}
			Expect(fakeClient.Get(ctx, client.ObjectKeyFromObject(existing), sa)).To(Succeed())
			Expect(sa.Labels[LabelDPUName]).To(Equal("dpu-01"))
			Expect(sa.Labels[LabelDPUUID]).To(Equal("test-uid-12345"))
		})

		It("builds the bootstrap kubeconfig from the token like a bootstrap token", func() {
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
			token, err := CreateDPUAgentServiceAccountToken(ctx, fakeClient, dpu, saNamespace)
			Expect(err).NotTo(HaveOccurred())

			data, err := GenerateBootstrapKubeconfig("https://10.0.0.1:6443", token, []byte("fake-ca-data"), "")
			Expect(err).NotTo(HaveOccurred())
			kubeconfig, err := clientcmd.Load(data)
			Expect(err).NotTo(HaveOccurred())
			Expect(kubeconfig.AuthInfos["default"].Token).To(Equal("fake-token"))
		})

		It("refuses a DPU without UID", func() {
			dpu.UID = ""
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()
			_, err := CreateDPUAgentServiceAccountToken(ctx, fakeClient, dpu, saNamespace)
			Expect(err).To(MatchError(ContainSubstring("has no UID")))
		})
	})

	Describe("DeleteDPUAgentBootstrapCredentials", func() {
		var bootstrapTokenSecret *corev1.Secret

		BeforeEach(func() {
			bootstrapTokenSecret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "bootstrap-token-abc123",
					Namespace: "kube-system",
					Labels: map[string]string{
						LabelDPUName:      "dpu-01",
						LabelDPUNamespace: "dpf-operator-system",
					},
				},
				Type: corev1.SecretTypeBootstrapToken,
			}
		})

		listBootstrapTokens := func(c client.Client) []corev1.Secret {
			secrets := &corev1.SecretList{}
			Expect(c.List(ctx, secrets, client.InNamespace("kube-system"))).To(Succeed())
			return secrets.Items
		}

		configWithNamespace := func(namespace string) *operatorv1.DPFOperatorConfig {
			return &operatorv1.DPFOperatorConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "dpfoperatorconfig", Namespace: "dpf-operator-system"},
				Spec: operatorv1.DPFOperatorConfigSpec{Security: &operatorv1.SecurityConfiguration{
					DPUAgentBootstrap: &operatorv1.DPUAgentBootstrapConfiguration{
						Method:                  operatorv1.DPUAgentBootstrapMethodServiceAccountToken,
						ServiceAccountNamespace: namespace,
					},
				}},
			}
		}

		It("deletes the bootstrap tokens of a bootstrap-token DPU without reading the config", func() {
			dpu.Status.IdentityMode = ptr.To(provisioningv1.IdentityModeBootstrapToken)
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bootstrapTokenSecret).Build()

			Expect(DeleteDPUAgentBootstrapCredentials(ctx, fakeClient, dpu)).To(Succeed())
			Expect(listBootstrapTokens(fakeClient)).To(BeEmpty())
		})

		It("deletes the ServiceAccounts of a service-account-token DPU in the configured namespace only", func() {
			mine := newServiceAccount("dpu-agent-test-uid-12345", "dpu-01")
			stale := newServiceAccount("dpu-agent-of-an-earlier-dpu-01", "dpu-01")
			other := newServiceAccount("dpu-agent-other", "dpu-02")
			elsewhere := newServiceAccount("dpu-agent-test-uid-12345", "dpu-01")
			elsewhere.Namespace = "tenant"
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).
				WithObjects(configWithNamespace(saNamespace), bootstrapTokenSecret, mine, stale, other, elsewhere).Build()

			Expect(DeleteDPUAgentBootstrapCredentials(ctx, fakeClient, dpu)).To(Succeed())
			Expect(listBootstrapTokens(fakeClient)).To(BeEmpty())
			Expect(listServiceAccounts(fakeClient, saNamespace)).To(ConsistOf("dpu-agent-other"))
			Expect(listServiceAccounts(fakeClient, "tenant")).To(ConsistOf("dpu-agent-test-uid-12345"))
		})

		It("falls back to the default namespace without a DPFOperatorConfig", func() {
			sa := newServiceAccount("dpu-agent-test-uid-12345", "dpu-01")
			sa.Namespace = operatorv1.DefaultDPUAgentBootstrapServiceAccountNamespace
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sa).Build()

			Expect(DeleteDPUAgentBootstrapCredentials(ctx, fakeClient, dpu)).To(Succeed())
			Expect(listServiceAccounts(fakeClient, operatorv1.DefaultDPUAgentBootstrapServiceAccountNamespace)).To(BeEmpty())
		})

		It("does not fail when nothing is left to delete", func() {
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(configWithNamespace(saNamespace)).Build()
			Expect(DeleteDPUAgentBootstrapCredentials(ctx, fakeClient, dpu)).To(Succeed())
		})
	})
})
