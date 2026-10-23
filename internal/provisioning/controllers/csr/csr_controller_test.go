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

package csr

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"

	operatorv1 "github.com/nvidia/doca-platform/api/operator/v1alpha1"
	provisioningv1 "github.com/nvidia/doca-platform/api/provisioning/v1alpha1"
	cutil "github.com/nvidia/doca-platform/internal/provisioning/controllers/util"
	hostutil "github.com/nvidia/doca-platform/internal/provisioning/hostagent/util"
	providentity "github.com/nvidia/doca-platform/internal/provisioning/utils/certificate/identity"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	certmanager "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("CSR Controller", func() {
	Describe("shouldProcessCSRObject", func() {
		It("selects host-agent bootstrap group", func() {
			Expect(shouldProcessCSRObject(&certmanager.CertificateSigningRequest{
				Spec: certmanager.CertificateSigningRequestSpec{
					Groups: []string{hostAgentBootstrapGroup},
				},
			})).To(BeTrue())
		})

		It("selects dpu-agent bootstrap group", func() {
			Expect(shouldProcessCSRObject(&certmanager.CertificateSigningRequest{
				Spec: certmanager.CertificateSigningRequestSpec{
					Groups: []string{cutil.DPUAgentBootstrapGroup},
				},
			})).To(BeTrue())
		})

		It("selects dpu-agent certificate organization group", func() {
			Expect(shouldProcessCSRObject(&certmanager.CertificateSigningRequest{
				Spec: certmanager.CertificateSigningRequestSpec{
					Groups: []string{providentity.DPUAgentOrganization},
				},
			})).To(BeTrue())
		})

		It("selects ServiceAccount requesters, whose namespace Reconcile checks", func() {
			Expect(shouldProcessCSRObject(&certmanager.CertificateSigningRequest{
				Spec: certmanager.CertificateSigningRequestSpec{
					Username: "system:serviceaccount:any-namespace:any-name",
					Groups:   []string{"system:serviceaccounts", "system:serviceaccounts:any-namespace", "system:authenticated"},
				},
			})).To(BeTrue())
		})

		It("ignores unrelated groups", func() {
			Expect(shouldProcessCSRObject(&certmanager.CertificateSigningRequest{
				Spec: certmanager.CertificateSigningRequestSpec{
					Groups: []string{"system:authenticated"},
				},
			})).To(BeFalse())
		})

		It("ignores non-CSR objects", func() {
			Expect(shouldProcessCSRObject(&corev1.Secret{})).To(BeFalse())
		})
	})

	Describe("isDPUAgentCSR", func() {
		It("treats dpu bootstrap csr as dpu-agent csr", func() {
			Expect(isDPUAgentCSR(&certmanager.CertificateSigningRequest{
				Spec: certmanager.CertificateSigningRequestSpec{
					Groups: []string{cutil.DPUAgentBootstrapGroup},
				},
			})).To(BeTrue())
		})

		It("treats dpu organization csr as dpu-agent csr", func() {
			Expect(isDPUAgentCSR(&certmanager.CertificateSigningRequest{
				Spec: certmanager.CertificateSigningRequestSpec{
					Groups: []string{providentity.DPUAgentOrganization},
				},
			})).To(BeTrue())
		})

		It("does not treat unrelated csr as dpu-agent csr", func() {
			Expect(isDPUAgentCSR(&certmanager.CertificateSigningRequest{
				Spec: certmanager.CertificateSigningRequestSpec{
					Groups: []string{"unrelated-group"},
				},
			})).To(BeFalse())
		})
	})

	Describe("validateDPUAgentCSR", func() {
		It("accepts valid DPU agent CSR", func() {
			reconciler := &CSRReconciler{
				RuntimeClient: newFakeRuntimeClient(newTestDPU()),
			}

			csr := newTestCSR(testCSRSpec{
				username:     providentity.DPUAgentUsername("dpu-01"),
				commonName:   providentity.DPUAgentUsername("dpu-01"),
				organization: []string{providentity.DPUAgentOrganization},
				signerName:   certmanager.KubeAPIServerClientSignerName,
			})

			Expect(reconciler.validateDPUAgentCSR(ctx, csr)).To(Succeed())
		})

		It("reports an error for unsupported signer", func() {
			reconciler := &CSRReconciler{
				RuntimeClient: newFakeRuntimeClient(newTestDPU()),
			}

			csr := newTestCSR(testCSRSpec{
				username:     providentity.DPUAgentUsername("dpu-01"),
				commonName:   providentity.DPUAgentUsername("dpu-01"),
				organization: []string{providentity.DPUAgentOrganization},
				signerName:   "example.com/custom-signer",
			})

			expectValidationErrorContains(reconciler.validateDPUAgentCSR(ctx, csr), "unsupported signer")
		})

		It("reports an error for invalid common name", func() {
			reconciler := &CSRReconciler{
				RuntimeClient: newFakeRuntimeClient(newTestDPU()),
			}

			csr := newTestCSR(testCSRSpec{
				commonName:   "not-a-dpu-agent",
				organization: []string{providentity.DPUAgentOrganization},
				signerName:   certmanager.KubeAPIServerClientSignerName,
			})

			expectValidationErrorContains(reconciler.validateDPUAgentCSR(ctx, csr), "must match da-{dpu-name}")
		})

		It("reports an error for invalid organization", func() {
			reconciler := &CSRReconciler{
				RuntimeClient: newFakeRuntimeClient(newTestDPU()),
			}

			csr := newTestCSR(testCSRSpec{
				commonName:   providentity.DPUAgentUsername("dpu-01"),
				organization: []string{"system:nodes"},
				signerName:   certmanager.KubeAPIServerClientSignerName,
			})

			expectValidationErrorContains(reconciler.validateDPUAgentCSR(ctx, csr), "organization must be")
		})

		It("reports an error when the DPU does not exist", func() {
			reconciler := &CSRReconciler{
				RuntimeClient: newFakeRuntimeClient(),
			}

			csr := newTestCSR(testCSRSpec{
				username:     providentity.DPUAgentUsername("dpu-01"),
				commonName:   providentity.DPUAgentUsername("dpu-01"),
				organization: []string{providentity.DPUAgentOrganization},
				signerName:   certmanager.KubeAPIServerClientSignerName,
			})

			expectValidationErrorContains(reconciler.validateDPUAgentCSR(ctx, csr), "DPU "+hostutil.DPFNamespace+"/dpu-01 not found")
		})

		Context("with a ServiceAccount requester", func() {
			var (
				dpu *provisioningv1.DPU
				sa  *corev1.ServiceAccount
			)

			BeforeEach(func() {
				dpu = newTestDPUNamed("dpu-01", testDPUUID, ptr.To(provisioningv1.IdentityModeServiceAccountToken))
				sa = newTestServiceAccount(testSANamespace, dpu)
			})

			It("accepts the ServiceAccount minted for the DPU", func() {
				reconciler := &CSRReconciler{RuntimeClient: newFakeRuntimeClient(dpu, sa)}
				Expect(reconciler.validateDPUAgentCSR(ctx, newTestServiceAccountCSR(sa, "dpu-01"))).To(Succeed())
			})

			It("reports an error for a certificate of another DPU", func() {
				other := newTestDPUNamed("dpu-02", "other-uid", ptr.To(provisioningv1.IdentityModeServiceAccountToken))
				reconciler := &CSRReconciler{RuntimeClient: newFakeRuntimeClient(dpu, other, sa)}
				expectValidationErrorContains(reconciler.validateDPUAgentCSR(ctx, newTestServiceAccountCSR(sa, "dpu-02")), "may not request a certificate for DPU dpu-02")
			})

			It("reports an error for an unknown ServiceAccount", func() {
				reconciler := &CSRReconciler{RuntimeClient: newFakeRuntimeClient(dpu)}
				expectValidationErrorContains(reconciler.validateDPUAgentCSR(ctx, newTestServiceAccountCSR(sa, "dpu-01")), "not found")
			})

			It("reports an error for a ServiceAccount not labeled with its DPU", func() {
				sa.Labels = map[string]string{cutil.LabelDPUName: "dpu-01"}
				reconciler := &CSRReconciler{RuntimeClient: newFakeRuntimeClient(dpu, sa)}
				expectValidationErrorContains(reconciler.validateDPUAgentCSR(ctx, newTestServiceAccountCSR(sa, "dpu-01")), "not labeled with its DPU")
			})

			It("reports an error for a requester that is not the ServiceAccount of that name", func() {
				reconciler := &CSRReconciler{RuntimeClient: newFakeRuntimeClient(dpu, sa)}
				csr := newTestServiceAccountCSR(sa, "dpu-01")
				csr.Spec.UID = "uid-of-a-deleted-serviceaccount"
				expectValidationErrorContains(reconciler.validateDPUAgentCSR(ctx, csr), "does not match bootstrap ServiceAccount")
			})

			It("reports an error for a ServiceAccount minted for a DPU since recreated", func() {
				recreated := newTestDPUNamed("dpu-01", "uid-of-the-new-dpu", ptr.To(provisioningv1.IdentityModeServiceAccountToken))
				reconciler := &CSRReconciler{RuntimeClient: newFakeRuntimeClient(recreated, sa)}
				expectValidationErrorContains(reconciler.validateDPUAgentCSR(ctx, newTestServiceAccountCSR(sa, "dpu-01")), "was minted for another DPU")
			})

			It("reports an error for a DPU in another identity mode", func() {
				dpu.Status.IdentityMode = ptr.To(provisioningv1.IdentityModeBootstrapToken)
				reconciler := &CSRReconciler{RuntimeClient: newFakeRuntimeClient(dpu, sa)}
				expectValidationErrorContains(reconciler.validateDPUAgentCSR(ctx, newTestServiceAccountCSR(sa, "dpu-01")), "does not use the service-account-token identity mode")
			})
		})
	})

	Describe("Reconcile", func() {
		var (
			dpu *provisioningv1.DPU
			cfg *operatorv1.DPFOperatorConfig
		)

		BeforeEach(func() {
			dpu = newTestDPUNamed("dpu-01", testDPUUID, ptr.To(provisioningv1.IdentityModeServiceAccountToken))
			cfg = &operatorv1.DPFOperatorConfig{
				ObjectMeta: metav1.ObjectMeta{Name: "dpfoperatorconfig", Namespace: hostutil.DPFNamespace},
				Spec: operatorv1.DPFOperatorConfigSpec{
					Security: &operatorv1.SecurityConfiguration{
						DPUAgentBootstrap: &operatorv1.DPUAgentBootstrapConfiguration{
							Method:                  operatorv1.DPUAgentBootstrapMethodServiceAccountToken,
							ServiceAccountNamespace: testSANamespace,
						},
					},
				},
			}
		})

		reconcile := func(csr *certmanager.CertificateSigningRequest, objects ...client.Object) *certmanager.CertificateSigningRequest {
			clientSet := k8sfake.NewClientset(csr.DeepCopy())
			reconciler := &CSRReconciler{
				RuntimeClient: newFakeRuntimeClient(append(objects, csr)...),
				ClientSet:     clientSet,
			}
			_, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(csr)})
			Expect(err).NotTo(HaveOccurred())
			reconciled, err := clientSet.CertificatesV1().CertificateSigningRequests().Get(ctx, csr.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			return reconciled
		}

		It("approves the CSR of a bootstrap ServiceAccount for its own DPU", func() {
			sa := newTestServiceAccount(testSANamespace, dpu)
			reconciled := reconcile(newTestServiceAccountCSR(sa, "dpu-01"), cfg, dpu, sa)
			Expect(reconciled.Status.Conditions).To(ConsistOf(And(
				HaveField("Type", certmanager.CertificateApproved),
				HaveField("Reason", dpuAgentApprovedReason),
			)))
		})

		It("leaves pending the CSR of a bootstrap ServiceAccount for another DPU", func() {
			sa := newTestServiceAccount(testSANamespace, dpu)
			other := newTestDPUNamed("dpu-02", "other-uid", ptr.To(provisioningv1.IdentityModeServiceAccountToken))
			reconciled := reconcile(newTestServiceAccountCSR(sa, "dpu-02"), cfg, dpu, other, sa)
			Expect(reconciled.Status.Conditions).To(BeEmpty())
		})

		It("leaves alone the CSR of a ServiceAccount in another namespace, even labeled like ours", func() {
			sa := newTestServiceAccount("tenant", dpu)
			reconciled := reconcile(newTestServiceAccountCSR(sa, "dpu-01"), cfg, dpu, sa)
			Expect(reconciled.Status.Conditions).To(BeEmpty())
		})

		It("leaves alone ServiceAccount CSRs while the configured namespace is the default", func() {
			cfg.Spec.Security = nil
			sa := newTestServiceAccount(testSANamespace, dpu)
			reconciled := reconcile(newTestServiceAccountCSR(sa, "dpu-01"), cfg, dpu, sa)
			Expect(reconciled.Status.Conditions).To(BeEmpty())
		})

		It("leaves alone ServiceAccount CSRs while the ServiceAccountToken method is not selected", func() {
			cfg.Spec.Security.DPUAgentBootstrap.Method = operatorv1.DPUAgentBootstrapMethodBootstrapToken
			sa := newTestServiceAccount(testSANamespace, dpu)
			reconciled := reconcile(newTestServiceAccountCSR(sa, "dpu-01"), cfg, dpu, sa)
			Expect(reconciled.Status.Conditions).To(BeEmpty())
		})

		It("still approves host agent CSRs", func() {
			csr := newTestCSR(testCSRSpec{
				username:   "system:bootstrap:def456",
				groups:     []string{hostAgentBootstrapGroup},
				commonName: "system:node:host-01",
				signerName: certmanager.KubeAPIServerClientSignerName,
			})
			reconciled := reconcile(csr, cfg)
			Expect(reconciled.Status.Conditions).To(ConsistOf(HaveField("Reason", hostAgentApprovedReason)))
		})
	})
})

const (
	testSANamespace = "dpu-agent-bootstrap-test"
	testDPUUID      = "3c1e5a8e-0000-4000-8000-000000000001"
)

type testCSRSpec struct {
	username     string
	uid          string
	groups       []string
	commonName   string
	organization []string
	signerName   string
}

func newTestCSR(spec testCSRSpec) *certmanager.CertificateSigningRequest {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())

	requestDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   spec.commonName,
			Organization: spec.organization,
		},
	}, privateKey)
	Expect(err).NotTo(HaveOccurred())

	return &certmanager.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-csr",
		},
		Spec: certmanager.CertificateSigningRequestSpec{
			Request:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: requestDER}),
			SignerName: spec.signerName,
			Username:   spec.username,
			UID:        spec.uid,
			Groups:     spec.groups,
		},
	}
}

func newFakeRuntimeClient(objects ...client.Object) client.Client {
	scheme := runtime.NewScheme()
	Expect(provisioningv1.AddToScheme(scheme)).To(Succeed())
	Expect(operatorv1.AddToScheme(scheme)).To(Succeed())
	Expect(clientgoscheme.AddToScheme(scheme)).To(Succeed())

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}

func newTestDPU() *provisioningv1.DPU {
	return newTestDPUNamed("dpu-01", "", nil)
}

func newTestDPUNamed(name, uid string, identityMode *provisioningv1.IdentityMode) *provisioningv1.DPU {
	return &provisioningv1.DPU{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: hostutil.DPFNamespace,
			UID:       types.UID(uid),
		},
		Status: provisioningv1.DPUStatus{IdentityMode: identityMode},
	}
}

func newTestServiceAccount(namespace string, dpu *provisioningv1.DPU) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cutil.DPUAgentServiceAccountName(dpu),
			Namespace: namespace,
			UID:       types.UID("sa-uid-" + dpu.Name),
			Labels: map[string]string{
				cutil.LabelDPUName:      dpu.Name,
				cutil.LabelDPUNamespace: dpu.Namespace,
				cutil.LabelDPUUID:       string(dpu.UID),
			},
		},
	}
}

// newTestServiceAccountCSR returns a CSR for the DPU agent certificate of dpuName, as the
// kube-apiserver records it when sa creates it.
func newTestServiceAccountCSR(sa *corev1.ServiceAccount, dpuName string) *certmanager.CertificateSigningRequest {
	return newTestCSR(testCSRSpec{
		username:     serviceaccount.MakeUsername(sa.Namespace, sa.Name),
		uid:          string(sa.UID),
		groups:       append(serviceaccount.MakeGroupNames(sa.Namespace), "system:authenticated"),
		commonName:   providentity.DPUAgentUsername(dpuName),
		organization: []string{providentity.DPUAgentOrganization},
		signerName:   certmanager.KubeAPIServerClientSignerName,
	})
}

func expectValidationErrorContains(err error, wantSubstring string) {
	var validationErr *csrValidationError
	Expect(errors.As(err, &validationErr)).To(BeTrue(), "expected csrValidationError")
	Expect(validationErr.Error()).To(ContainSubstring(wantSubstring))
}
