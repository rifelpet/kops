/*
Copyright 2021 The Kubernetes Authors.

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

package controllers

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	csrv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	csrv1client "k8s.io/client-go/kubernetes/typed/certificates/v1"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// NewCSRReconciler is the constructor for a CSRReconciler
func NewCSRReconciler(mgr manager.Manager) (*CSRReconciler, error) {
	r := &CSRReconciler{
		client: mgr.GetClient(),
		log:    ctrl.Log.WithName("controllers").WithName("Node"),
	}

	certClient, err := csrv1client.NewForConfig(mgr.GetConfig())
	if err != nil {
		return nil, fmt.Errorf("error building csrv1 client: %v", err)
	}
	r.csrv1Client = certClient

	return r, nil
}

// CSRReconciler observes CertificateSigningRequest objects and approves them for nodes joining the cluster
// This is for certain node operating systems that do not support running nodeup
type CSRReconciler struct {
	// client is the controller-runtime client
	client client.Client

	// log is a logr
	log logr.Logger

	// csrv1Client is a client-go client for updating CSRs
	csrv1Client *csrv1client.CertificatesV1Client
}

// +kubebuilder:rbac:groups=certificates,resources=certificatesigningrequest,verbs=get;list;watch;patch
// Reconcile is the main reconciler function that observes node changes.
func (r *CSRReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	_ = r.log.WithValues("csrcontroller", req.NamespacedName)

	csr := &csrv1.CertificateSigningRequest{}
	if err := r.client.Get(ctx, req.NamespacedName, csr); err != nil {
		klog.Warningf("unable to fetch csr %s: %v", csr.Name, err)
		if apierrors.IsNotFound(err) {
			// we'll ignore not-found errors, since they can't be fixed by an immediate
			// requeue (we'll need to wait for a new notification), and we can get them
			// on deleted requests.
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	// We only care about pending CSRs for kubelet server certificates
	if csr.Spec.SignerName != csrv1.KubeletServingSignerName || !isCSRPending(csr.Status) {
		return ctrl.Result{}, nil
	}
	appendApprovalCondition(csr)
	_, err := r.csrv1Client.CertificateSigningRequests().UpdateApproval(ctx, csr.Name, csr, v1.UpdateOptions{})
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *CSRReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&csrv1.CertificateSigningRequest{}).
		Complete(r)
}

func isCSRPending(status csrv1.CertificateSigningRequestStatus) bool {
	for _, c := range status.Conditions {
		if len(c.Status) != 0 && c.Status != corev1.ConditionTrue {
			continue
		}
		if c.Type == csrv1.CertificateApproved || c.Type == csrv1.CertificateDenied || c.Type == csrv1.CertificateFailed {
			return false
		}
	}
	return true
}

func appendApprovalCondition(csr *csrv1.CertificateSigningRequest) {
	csr.Status.Conditions = append(csr.Status.Conditions, csrv1.CertificateSigningRequestCondition{
		Type:    csrv1.CertificateApproved,
		Status:  corev1.ConditionTrue,
		Reason:  "AutoApproved",
		Message: "Approved kubelet server certificate by kops-controller",
	})
}
