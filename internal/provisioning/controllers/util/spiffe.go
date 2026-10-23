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
	operatorv1 "github.com/nvidia/doca-platform/api/operator/v1alpha1"
	provisioningv1 "github.com/nvidia/doca-platform/api/provisioning/v1alpha1"
)

// SpiffeEnabled reports whether the cluster DPFOperatorConfig opts into the SPIFFE
// DPU Agent identity flow. It is the single gate the provisioning controllers use to
// decide which identity mode to stamp onto a freshly initialized DPU.
func SpiffeEnabled(cfg *operatorv1.DPFOperatorConfig) bool {
	return cfg != nil && cfg.Spec.Security != nil && cfg.Spec.Security.SPIFFE != nil
}

// ServiceAccountTokenBootstrapEnabled reports whether the cluster DPFOperatorConfig selects the
// ServiceAccountToken DPU Agent bootstrap method.
func ServiceAccountTokenBootstrapEnabled(cfg *operatorv1.DPFOperatorConfig) bool {
	return cfg != nil && cfg.Spec.Security.DPUAgentBootstrapMethod() == operatorv1.DPUAgentBootstrapMethodServiceAccountToken
}

// DPUAgentServiceAccountNamespace returns the namespace holding the per-DPU bootstrap
// ServiceAccounts. It is defined whatever the configured method, because a DPU keeps the
// identity mode DPF set when it was initialized.
func DPUAgentServiceAccountNamespace(cfg *operatorv1.DPFOperatorConfig) string {
	if cfg == nil {
		return operatorv1.DefaultDPUAgentBootstrapServiceAccountNamespace
	}
	return cfg.Spec.Security.DPUAgentBootstrapServiceAccountNamespace()
}

// IdentityModeForConfig returns the identity mode DPF sets on a DPU when it is initialized. The
// API server rejects a config combining SPIFFE with the ServiceAccountToken bootstrap method.
func IdentityModeForConfig(cfg *operatorv1.DPFOperatorConfig) provisioningv1.IdentityMode {
	switch {
	case SpiffeEnabled(cfg):
		return provisioningv1.IdentityModeSpiffe
	case ServiceAccountTokenBootstrapEnabled(cfg):
		return provisioningv1.IdentityModeServiceAccountToken
	default:
		return provisioningv1.IdentityModeBootstrapToken
	}
}

// IsSpiffeDPU reports whether the DPU has been stamped with the SPIFFE identity mode.
// A DPU with an unset IdentityMode is treated as bootstrap-token (legacy) and is not a
// SPIFFE DPU.
func IsSpiffeDPU(dpu *provisioningv1.DPU) bool {
	return dpu != nil && dpu.Status.IdentityMode != nil &&
		*dpu.Status.IdentityMode == provisioningv1.IdentityModeSpiffe
}

// IsBootstrapTokenDPU reports whether the DPU uses the bootstrap-token identity mode.
// An unset (nil) IdentityMode is treated semantically as bootstrap-token per the API
// contract, so legacy DPUs provisioned before SPIFFE return true.
func IsBootstrapTokenDPU(dpu *provisioningv1.DPU) bool {
	if dpu == nil {
		return false
	}
	return dpu.Status.IdentityMode == nil ||
		*dpu.Status.IdentityMode == provisioningv1.IdentityModeBootstrapToken
}

// IsServiceAccountTokenDPU reports whether the DPU bootstraps the DPU Agent with a ServiceAccount
// token.
func IsServiceAccountTokenDPU(dpu *provisioningv1.DPU) bool {
	return dpu != nil && dpu.Status.IdentityMode != nil &&
		*dpu.Status.IdentityMode == provisioningv1.IdentityModeServiceAccountToken
}
