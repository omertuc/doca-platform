/*
Copyright 2025 NVIDIA

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
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	provisioningv1 "github.com/nvidia/doca-platform/api/provisioning/v1alpha1"
	cutil "github.com/nvidia/doca-platform/internal/provisioning/controllers/util"
	hostutil "github.com/nvidia/doca-platform/internal/provisioning/hostagent/util"
	providentity "github.com/nvidia/doca-platform/internal/provisioning/utils/certificate/identity"
	dpfutils "github.com/nvidia/doca-platform/internal/utils"
	"github.com/nvidia/doca-platform/internal/utils/tracing"

	certmanager "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	clientset "k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const (
	// CSRControllerName is the span name of the certificate-signing-request reconciler.
	CSRControllerName       = "csr"
	hostAgentBootstrapGroup = "system:bootstrappers:dpf:host-agent"
	dpuAgentApprovedReason  = "DPUAgentApproved"
	hostAgentApprovedReason = "HostAgentApproved"
)

type CSRReconciler struct {
	RuntimeClient client.Client
	ClientSet     clientset.Interface
}

// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/approval;certificatesigningrequests/status,verbs=update
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=signers,resourceNames="kubernetes.io/kube-apiserver-client",verbs=approve

func (r *CSRReconciler) Reconcile(ctx context.Context, req ctrl.Request) (_ ctrl.Result, reterr error) {
	log := ctrllog.FromContext(ctx)

	csr := &certmanager.CertificateSigningRequest{}
	if err := r.RuntimeClient.Get(ctx, req.NamespacedName, csr); err != nil {
		return ctrl.Result{}, err
	}
	ctx, endSpan := tracing.ReconcileSpan(ctx, CSRControllerName, csr)
	defer endSpan(&reterr)

	needApprove := true
	var approvalStatus certmanager.RequestConditionType
	for _, cond := range csr.Status.Conditions {
		switch cond.Type {
		case certmanager.CertificateApproved, certmanager.CertificateDenied:
			needApprove = false
			approvalStatus = cond.Type
		}
	}
	if !needApprove {
		log.V(3).Info("CSR already approved or denied, skipped", "name", csr.Name, "approval status", approvalStatus)
		return ctrl.Result{}, nil
	}

	// A ServiceAccount is only a DPU agent bootstrapping in the namespace dedicated to their
	// ServiceAccounts. Any other is not ours to approve, as host agent or otherwise.
	if isServiceAccountCSR(csr) {
		ours, err := r.isDPUAgentServiceAccountCSR(ctx, csr)
		if err != nil {
			return ctrl.Result{}, err
		}
		if !ours {
			log.V(3).Info("CSR from a ServiceAccount outside the DPU agent bootstrap namespace, skipped", "name", csr.Name, "username", csr.Spec.Username)
			return ctrl.Result{}, nil
		}
	}

	approvalReason := hostAgentApprovedReason
	approvalLogMessage := "Host agent CSR approved"
	if isDPUAgentCSR(csr) || isServiceAccountCSR(csr) {
		if err := r.validateDPUAgentCSR(ctx, csr); err != nil {
			var validationErr *csrValidationError
			if errors.As(err, &validationErr) {
				// Keep invalid DPU agent CSRs pending so the certificate manager does
				// not immediately create a replacement CSR and flood the cluster.
				log.Info("DPU agent CSR validation failed, leaving pending", "name", csr.Name, "error", validationErr.Error())
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, err
		}
		approvalReason = dpuAgentApprovedReason
		approvalLogMessage = "DPU agent CSR approved"
	}

	if err := r.updateApprovalCondition(ctx, csr, certmanager.CertificateApproved, approvalReason, "approved by controller"); err != nil {
		return ctrl.Result{}, err
	}
	log.Info(approvalLogMessage, "name", csr.Name)
	return ctrl.Result{}, nil
}

func (r *CSRReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certmanager.CertificateSigningRequest{}, builder.WithPredicates(predicate.NewPredicateFuncs(shouldProcessCSRObject))).
		Complete(r)
}

func shouldProcessCSRObject(o client.Object) bool {
	csr, ok := o.(*certmanager.CertificateSigningRequest)
	if !ok {
		return false
	}
	for _, group := range csr.Spec.Groups {
		if group == hostAgentBootstrapGroup || group == cutil.DPUAgentBootstrapGroup || group == providentity.DPUAgentOrganization {
			return true
		}
	}
	// The namespace of the DPU agent bootstrap ServiceAccounts is configurable, so a predicate
	// cannot tell them from other ServiceAccounts. Reconcile tells them apart.
	return isServiceAccountCSR(csr)
}

type csrValidationError struct {
	message string
}

func (e *csrValidationError) Error() string {
	return e.message
}

func newCSRValidationError(format string, args ...any) error {
	return &csrValidationError{
		message: fmt.Sprintf(format, args...),
	}
}

func isDPUAgentCSR(csr *certmanager.CertificateSigningRequest) bool {
	for _, group := range csr.Spec.Groups {
		if group == cutil.DPUAgentBootstrapGroup || group == providentity.DPUAgentOrganization {
			return true
		}
	}
	return false
}

// serviceAccountRequester returns the namespace and name of the ServiceAccount that created the
// CSR, if a ServiceAccount did.
func serviceAccountRequester(csr *certmanager.CertificateSigningRequest) (namespace, name string, ok bool) {
	namespace, name, err := serviceaccount.SplitUsername(csr.Spec.Username)
	if err != nil {
		return "", "", false
	}
	return namespace, name, true
}

func isServiceAccountCSR(csr *certmanager.CertificateSigningRequest) bool {
	_, _, ok := serviceAccountRequester(csr)
	return ok
}

// isDPUAgentServiceAccountCSR reports whether the CSR was created by a ServiceAccount in the
// namespace that the DPFOperatorConfig dedicates to DPU agent bootstrap ServiceAccounts. The
// namespace is only dedicated to them, and only exists, while the ServiceAccountToken method is
// selected.
func (r *CSRReconciler) isDPUAgentServiceAccountCSR(ctx context.Context, csr *certmanager.CertificateSigningRequest) (bool, error) {
	namespace, _, ok := serviceAccountRequester(csr)
	if !ok {
		return false, nil
	}
	cfg, err := dpfutils.GetDPFOperatorConfig(ctx, r.RuntimeClient)
	if err != nil {
		return false, fmt.Errorf("getting DPFOperatorConfig for the DPU agent bootstrap ServiceAccount namespace: %w", err)
	}
	return cutil.ServiceAccountTokenBootstrapEnabled(cfg) && namespace == cutil.DPUAgentServiceAccountNamespace(cfg), nil
}

// validateDPUAgentCSR checks that the CSR asks for a DPU agent client certificate of an existing
// DPU, and, when a bootstrap ServiceAccount sent it, that DPF created the ServiceAccount for that
// DPU.
func (r *CSRReconciler) validateDPUAgentCSR(ctx context.Context, csr *certmanager.CertificateSigningRequest) error {
	if csr.Spec.SignerName != certmanager.KubeAPIServerClientSignerName {
		return newCSRValidationError("unsupported signer %q", csr.Spec.SignerName)
	}

	block, _ := pem.Decode(csr.Spec.Request)
	if block == nil {
		return newCSRValidationError("invalid CSR PEM payload")
	}

	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return newCSRValidationError("parsing CSR request: %v", err)
	}
	if err := request.CheckSignature(); err != nil {
		return newCSRValidationError("invalid CSR signature: %v", err)
	}

	dpuName, ok := providentity.DPUNameFromAgentUsername(request.Subject.CommonName)
	if !ok {
		return newCSRValidationError("common name %q must match da-{dpu-name}", request.Subject.CommonName)
	}
	if len(request.Subject.Organization) != 1 || request.Subject.Organization[0] != providentity.DPUAgentOrganization {
		return newCSRValidationError("organization must be %q", providentity.DPUAgentOrganization)
	}

	if saNamespace, saName, ok := serviceAccountRequester(csr); ok {
		return r.validateServiceAccountRequester(ctx, csr, saNamespace, saName, dpuName)
	}
	_, err = r.getDPU(ctx, hostutil.DPFNamespace, dpuName)
	return err
}

// validateServiceAccountRequester checks that the bootstrap ServiceAccount that created the CSR
// was minted for the DPU the CSR is for. The ServiceAccount labels name that DPU, and its UID
// guards against a DPU deleted and recreated under the same name.
func (r *CSRReconciler) validateServiceAccountRequester(ctx context.Context, csr *certmanager.CertificateSigningRequest, saNamespace, saName, dpuName string) error {
	sa := &corev1.ServiceAccount{}
	if err := r.RuntimeClient.Get(ctx, client.ObjectKey{Namespace: saNamespace, Name: saName}, sa); err != nil {
		if apierrors.IsNotFound(err) {
			return newCSRValidationError("bootstrap ServiceAccount %s/%s not found", saNamespace, saName)
		}
		return fmt.Errorf("getting bootstrap ServiceAccount %s/%s: %w", saNamespace, saName, err)
	}
	// The token authenticator sets the user UID to the ServiceAccount UID.
	if csr.Spec.UID != string(sa.UID) {
		return newCSRValidationError("requester UID %q does not match bootstrap ServiceAccount %s/%s", csr.Spec.UID, saNamespace, saName)
	}
	labeledName, labeledNamespace, labeledUID := sa.Labels[cutil.LabelDPUName], sa.Labels[cutil.LabelDPUNamespace], sa.Labels[cutil.LabelDPUUID]
	if labeledName == "" || labeledNamespace == "" || labeledUID == "" {
		return newCSRValidationError("bootstrap ServiceAccount %s/%s is not labeled with its DPU", saNamespace, saName)
	}
	if labeledName != dpuName {
		return newCSRValidationError("bootstrap ServiceAccount %s/%s of DPU %s/%s may not request a certificate for DPU %s", saNamespace, saName, labeledNamespace, labeledName, dpuName)
	}
	dpu, err := r.getDPU(ctx, labeledNamespace, labeledName)
	if err != nil {
		return err
	}
	if string(dpu.UID) != labeledUID {
		return newCSRValidationError("bootstrap ServiceAccount %s/%s was minted for another DPU %s/%s (UID %s)", saNamespace, saName, labeledNamespace, labeledName, labeledUID)
	}
	if !cutil.IsServiceAccountTokenDPU(dpu) {
		return newCSRValidationError("DPU %s/%s does not use the %s identity mode", labeledNamespace, labeledName, provisioningv1.IdentityModeServiceAccountToken)
	}
	return nil
}

func (r *CSRReconciler) getDPU(ctx context.Context, namespace, name string) (*provisioningv1.DPU, error) {
	dpu := &provisioningv1.DPU{}
	if err := r.RuntimeClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, dpu); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, newCSRValidationError("DPU %s/%s not found", namespace, name)
		}
		return nil, fmt.Errorf("getting DPU %s/%s: %w", namespace, name, err)
	}
	return dpu, nil
}

func (r *CSRReconciler) updateApprovalCondition(
	ctx context.Context,
	csr *certmanager.CertificateSigningRequest,
	conditionType certmanager.RequestConditionType,
	reason string,
	message string,
) error {
	csr = csr.DeepCopy()
	csr.Status.Conditions = append(csr.Status.Conditions, certmanager.CertificateSigningRequestCondition{
		Type:               conditionType,
		Status:             corev1.ConditionTrue,
		Reason:             reason,
		Message:            message,
		LastUpdateTime:     metav1.Now(),
		LastTransitionTime: metav1.Now(),
	})
	// The approval is written from a copy, so the reconciled csr looks unchanged and only this span
	// keeps its reconcile in the trace.
	return tracing.InSpan(ctx, "csr.k8s.updateApproval", func(ctx context.Context) error {
		_, err := r.ClientSet.CertificatesV1().CertificateSigningRequests().UpdateApproval(ctx, csr.Name, csr, metav1.UpdateOptions{})
		return err
	})
}
