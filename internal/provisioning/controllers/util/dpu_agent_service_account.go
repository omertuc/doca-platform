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
	"errors"
	"fmt"
	"time"

	provisioningv1 "github.com/nvidia/doca-platform/api/provisioning/v1alpha1"
	dpfutils "github.com/nvidia/doca-platform/internal/utils"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// LabelDPUUID is set, next to LabelDPUName and LabelDPUNamespace, on the bootstrap
	// ServiceAccount of a DPU. The labels, not the ServiceAccount name, map it back to its DPU.
	LabelDPUUID = DPUProvisioningPrefix + "dpu-uid"

	dpuAgentServiceAccountPrefix = "dpu-agent-"
)

// DPUAgentServiceAccountName returns the name of the bootstrap ServiceAccount of the DPU. It is
// derived from the DPU UID because the DPU name can be longer than a ServiceAccount name may be,
// and DPUs in different namespaces may share a name.
func DPUAgentServiceAccountName(dpu *provisioningv1.DPU) string {
	return dpuAgentServiceAccountPrefix + string(dpu.UID)
}

// CreateDPUAgentServiceAccountToken ensures the bootstrap ServiceAccount of the DPU exists in
// namespace and returns a fresh token of it, minted with the TokenRequest API. It is the
// service-account-token counterpart of CreateDPUAgentBootstrapToken.
//
// The token carries the API server's default audience. Its lifetime is requested like a bootstrap
// token's, but the API server may cap it (--service-account-max-token-expiration), so the
// expiration it reports is the one that holds.
func CreateDPUAgentServiceAccountToken(ctx context.Context, client crclient.Client, dpu *provisioningv1.DPU, namespace string) (string, error) {
	if dpu.UID == "" {
		return "", fmt.Errorf("DPU %s/%s has no UID", dpu.Namespace, dpu.Name)
	}
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      DPUAgentServiceAccountName(dpu),
			Namespace: namespace,
		},
	}
	// The ServiceAccount cannot be owned by the DPU, which lives in another namespace. It is
	// deleted explicitly, with DeleteDPUAgentBootstrapCredentials.
	if _, err := controllerutil.CreateOrPatch(ctx, client, sa, func() error {
		if sa.Labels == nil {
			sa.Labels = map[string]string{}
		}
		sa.Labels[LabelDPUName] = dpu.Name
		sa.Labels[LabelDPUNamespace] = dpu.Namespace
		sa.Labels[LabelDPUUID] = string(dpu.UID)
		// Nothing runs as this ServiceAccount: its only tokens are the ones minted here.
		sa.AutomountServiceAccountToken = ptr.To(false)
		return nil
	}); err != nil {
		return "", fmt.Errorf("ensuring bootstrap ServiceAccount %s/%s for DPU %s/%s: %w", sa.Namespace, sa.Name, dpu.Namespace, dpu.Name, err)
	}

	tokenRequest := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			ExpirationSeconds: ptr.To(int64(bootstrapTokenExpiration / time.Second)),
		},
	}
	if err := client.SubResource("token").Create(ctx, sa, tokenRequest); err != nil {
		return "", fmt.Errorf("requesting token for bootstrap ServiceAccount %s/%s: %w", sa.Namespace, sa.Name, err)
	}
	if tokenRequest.Status.Token == "" {
		return "", fmt.Errorf("token request for bootstrap ServiceAccount %s/%s returned no token", sa.Namespace, sa.Name)
	}
	log.FromContext(ctx).V(2).Info("minted DPU agent bootstrap ServiceAccount token",
		"serviceAccount", crclient.ObjectKeyFromObject(sa), "expiration", tokenRequest.Status.ExpirationTimestamp.Time)
	return tokenRequest.Status.Token, nil
}

// DeleteDPUAgentServiceAccounts deletes the bootstrap ServiceAccounts in namespace that belong to
// the specified DPU (identified by labels). Deleting a ServiceAccount revokes every token minted
// for it.
func DeleteDPUAgentServiceAccounts(ctx context.Context, client crclient.Client, dpuName, dpuNamespace, namespace string) error {
	saList := &corev1.ServiceAccountList{}
	if err := client.List(ctx, saList,
		crclient.InNamespace(namespace),
		crclient.MatchingLabels{
			LabelDPUName:      dpuName,
			LabelDPUNamespace: dpuNamespace,
		},
	); err != nil {
		return fmt.Errorf("listing bootstrap ServiceAccounts for DPU %s/%s: %w", dpuNamespace, dpuName, err)
	}
	for i := range saList.Items {
		if err := client.Delete(ctx, &saList.Items[i]); crclient.IgnoreNotFound(err) != nil {
			return fmt.Errorf("deleting bootstrap ServiceAccount %s/%s: %w", namespace, saList.Items[i].Name, err)
		}
	}
	return nil
}

// DeleteDPUAgentBootstrapCredentials revokes the credentials the DPU Agent of the DPU bootstraps
// with: its bootstrap tokens and, for a service-account-token DPU, its bootstrap ServiceAccounts.
func DeleteDPUAgentBootstrapCredentials(ctx context.Context, client crclient.Client, dpu *provisioningv1.DPU) error {
	if err := DeleteDPUAgentBootstrapTokens(ctx, client, dpu.Name, dpu.Namespace); err != nil {
		return err
	}
	if !IsServiceAccountTokenDPU(dpu) {
		return nil
	}
	// Without a DPFOperatorConfig, DPF is being uninstalled and the operator has removed the
	// namespace with everything in it; the default namespace is then as good a place to look.
	cfg, err := dpfutils.GetDPFOperatorConfig(ctx, client)
	if err != nil && !errors.Is(err, dpfutils.ErrDPFOperatorConfigNotFound) {
		return fmt.Errorf("getting DPFOperatorConfig for the bootstrap ServiceAccount namespace: %w", err)
	}
	return DeleteDPUAgentServiceAccounts(ctx, client, dpu.Name, dpu.Namespace, DPUAgentServiceAccountNamespace(cfg))
}
