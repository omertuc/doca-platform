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

package state_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"time"

	cutil "github.com/nvidia/doca-platform/internal/provisioning/controllers/util"
	providentity "github.com/nvidia/doca-platform/internal/provisioning/utils/certificate/identity"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	authenticationv1 "k8s.io/api/authentication/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// These run against a real kube-apiserver because the CSR approver relies on how it records a
// ServiceAccount requester, and on deleting the ServiceAccount revoking its tokens.
var _ = Describe("DPU agent bootstrap with a ServiceAccount token", func() {
	var saNamespace *corev1.Namespace

	BeforeEach(func() {
		saNamespace = &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "dpu-agent-bootstrap-"}}
		createObject(saNamespace)
	})

	reviewToken := func(token string) authenticationv1.TokenReviewStatus {
		review := &authenticationv1.TokenReview{Spec: authenticationv1.TokenReviewSpec{Token: token}}
		Expect(k8sClient.Create(ctx, review)).To(Succeed())
		return review.Status
	}

	It("mints a token that authenticates as the DPU's ServiceAccount until the ServiceAccount is deleted", func() {
		dpu := dpuObj("sa-bootstrap-dpu")
		dpu.Spec.DPUDeviceName = "sa-bootstrap-device"
		dpu.Spec.DPUNodeName = "sa-bootstrap-node"
		createObject(dpu)

		token, err := cutil.CreateDPUAgentServiceAccountToken(ctx, k8sClient, dpu, saNamespace.Name)
		Expect(err).NotTo(HaveOccurred())
		sa := &corev1.ServiceAccount{}
		Expect(k8sClient.Get(ctx, client.ObjectKey{Namespace: saNamespace.Name, Name: cutil.DPUAgentServiceAccountName(dpu)}, sa)).To(Succeed())
		Expect(sa.Labels).To(HaveKeyWithValue(cutil.LabelDPUUID, string(dpu.UID)))

		By("authenticating as the ServiceAccount")
		status := reviewToken(token)
		Expect(status.Authenticated).To(BeTrue())
		Expect(status.User.Username).To(Equal(serviceaccount.MakeUsername(sa.Namespace, sa.Name)))
		Expect(status.User.UID).To(Equal(string(sa.UID)))
		Expect(status.User.Groups).To(ContainElement(serviceaccount.MakeNamespaceGroupName(sa.Namespace)))

		By("creating a CSR the kube-apiserver records with the identity the approver checks")
		csrCreator := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "dpu-agent-csr-creator-"},
			Rules: []rbacv1.PolicyRule{{
				APIGroups: []string{certificatesv1.GroupName},
				Resources: []string{"certificatesigningrequests"},
				Verbs:     []string{"create", "get"},
			}},
		}
		createObject(csrCreator)
		createObject(&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "dpu-agent-sa-bootstrap-"},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: csrCreator.Name},
			Subjects: []rbacv1.Subject{{
				APIGroup: rbacv1.GroupName,
				Kind:     rbacv1.GroupKind,
				Name:     serviceaccount.MakeNamespaceGroupName(sa.Namespace),
			}},
		})
		tokenConfig := rest.AnonymousClientConfig(cfg)
		tokenConfig.BearerToken = token
		agentClient, err := kubernetes.NewForConfig(tokenConfig)
		Expect(err).NotTo(HaveOccurred())

		var csr *certificatesv1.CertificateSigningRequest
		Eventually(func() error {
			csr, err = agentClient.CertificatesV1().CertificateSigningRequests().Create(ctx, &certificatesv1.CertificateSigningRequest{
				ObjectMeta: metav1.ObjectMeta{GenerateName: "dpu-agent-"},
				Spec: certificatesv1.CertificateSigningRequestSpec{
					Request:    newDPUAgentCertificateRequest(dpu.Name),
					SignerName: certificatesv1.KubeAPIServerClientSignerName,
					Usages:     []certificatesv1.KeyUsage{certificatesv1.UsageClientAuth},
				},
			}, metav1.CreateOptions{})
			return err
		}).WithTimeout(10 * time.Second).Should(Succeed())
		testObjects = append(testObjects, csr)
		gotNamespace, gotName, err := serviceaccount.SplitUsername(csr.Spec.Username)
		Expect(err).NotTo(HaveOccurred())
		Expect(gotNamespace).To(Equal(sa.Namespace))
		Expect(gotName).To(Equal(sa.Name))
		Expect(csr.Spec.UID).To(Equal(string(sa.UID)))

		By("revoking the token with the ServiceAccount")
		Expect(cutil.DeleteDPUAgentServiceAccounts(ctx, k8sClient, dpu.Name, dpu.Namespace, saNamespace.Name)).To(Succeed())
		Eventually(func() bool {
			return reviewToken(token).Authenticated
		}).WithTimeout(10 * time.Second).Should(BeFalse())
	})
})

func newDPUAgentCertificateRequest(dpuName string) []byte {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   providentity.DPUAgentUsername(dpuName),
			Organization: []string{providentity.DPUAgentOrganization},
		},
	}, key)
	Expect(err).NotTo(HaveOccurred())
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}
