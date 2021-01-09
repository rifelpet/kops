/*
Copyright 2019 The Kubernetes Authors.

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

package bootstrapchannelbuilder

import (
	"fmt"
	"strings"

	"k8s.io/klog/v2"
	channelsapi "k8s.io/kops/channels/pkg/api"
	"k8s.io/kops/pkg/apis/kops"
	"k8s.io/kops/pkg/assets"
	"k8s.io/kops/pkg/featureflag"
	"k8s.io/kops/pkg/kubemanifest"
	"k8s.io/kops/pkg/model"
	"k8s.io/kops/pkg/model/components/addonmanifests"
	"k8s.io/kops/pkg/model/components/addonmanifests/dnscontroller"
	"k8s.io/kops/pkg/model/iam"
	"k8s.io/kops/pkg/templates"
	"k8s.io/kops/upup/pkg/fi"
	"k8s.io/kops/upup/pkg/fi/fitasks"
	"k8s.io/kops/upup/pkg/fi/utils"
)

// BootstrapChannelBuilder is responsible for handling the addons in channels
type BootstrapChannelBuilder struct {
	*model.KopsModelContext
	ClusterAddons kubemanifest.ObjectList
	Lifecycle     *fi.Lifecycle
	templates     *templates.Templates
	assetBuilder  *assets.AssetBuilder
}

var _ fi.ModelBuilder = &BootstrapChannelBuilder{}

// networkSelector is the labels set on networking addons
//
// The role.kubernetes.io/networking is used to label anything related to a networking addin,
// so that if we switch networking plugins (e.g. calico -> weave or vice-versa), we'll replace the
// old networking plugin, and there won't be old pods "floating around".
//
// This means whenever we create or update a networking plugin, we should be sure that:
// 1. the selector is role.kubernetes.io/networking=1
// 2. every object in the manifest is labeled with role.kubernetes.io/networking=1
//
// TODO: Some way to test/enforce this?
//
// TODO: Create "empty" configurations for others, so we can delete e.g. the kopeio configuration
// if we switch to kubenet?
//
// TODO: Create configuration object for cni providers (maybe create it but orphan it)?
//
// NOTE: we try to suffix with -kops.1, so that we can increment versions even if the upstream version
// hasn't changed.  The problem with semver is that there is nothing > 1.0.0 other than 1.0.1-pre.1
func networkingSelector() map[string]string {
	return map[string]string{"role.kubernetes.io/networking": "1"}
}

// NewBootstrapChannelBuilder creates a new BootstrapChannelBuilder
func NewBootstrapChannelBuilder(modelContext *model.KopsModelContext,
	clusterLifecycle *fi.Lifecycle, assetBuilder *assets.AssetBuilder,
	templates *templates.Templates,
	addons kubemanifest.ObjectList,
) *BootstrapChannelBuilder {
	return &BootstrapChannelBuilder{
		KopsModelContext: modelContext,
		Lifecycle:        clusterLifecycle,
		assetBuilder:     assetBuilder,
		templates:        templates,
		ClusterAddons:    addons,
	}
}

// Build is responsible for adding the addons to the channel
func (b *BootstrapChannelBuilder) Build(c *fi.ModelBuilderContext) error {
	addons, err := b.buildAddons(c)
	if err != nil {
		return err
	}

	if err := addons.Verify(); err != nil {
		return err
	}

	for _, a := range addons.Spec.Addons {
		key := *a.Name
		if a.Id != "" {
			key = key + "-" + a.Id
		}
		name := b.Cluster.ObjectMeta.Name + "-addons-" + key
		manifestPath := "addons/" + *a.Manifest
		klog.V(4).Infof("Addon %q", name)

		manifestResource := b.templates.Find(manifestPath)
		if manifestResource == nil {
			return fmt.Errorf("unable to find manifest %s", manifestPath)
		}

		manifestBytes, err := fi.ResourceAsBytes(manifestResource)
		if err != nil {
			return fmt.Errorf("error reading manifest %s: %v", manifestPath, err)
		}

		// Go through any transforms that are best expressed as code
		remapped, err := addonmanifests.RemapAddonManifest(a, b.KopsModelContext, b.assetBuilder, manifestBytes)
		if err != nil {
			klog.Infof("invalid manifest: %s", string(manifestBytes))
			return fmt.Errorf("error remapping manifest %s: %v", manifestPath, err)
		}
		manifestBytes = remapped

		// Trim whitespace
		manifestBytes = []byte(strings.TrimSpace(string(manifestBytes)))

		rawManifest := string(manifestBytes)
		klog.V(4).Infof("Manifest %v", rawManifest)

		manifestHash, err := utils.HashString(rawManifest)
		klog.V(4).Infof("hash %s", manifestHash)
		if err != nil {
			return fmt.Errorf("error hashing manifest: %v", err)
		}
		a.ManifestHash = manifestHash

		c.AddTask(&fitasks.ManagedFile{
			Contents:  fi.NewBytesResource(manifestBytes),
			Lifecycle: b.Lifecycle,
			Location:  fi.String(manifestPath),
			Name:      fi.String(name),
		})
	}

	if b.ClusterAddons != nil {
		key := "cluster-addons.kops.k8s.io"
		version := "0.0.0"
		location := key + "/default.yaml"

		a := &channelsapi.AddonSpec{
			Name:     fi.String(key),
			Version:  fi.String(version),
			Selector: map[string]string{"k8s-addon": key},
			Manifest: fi.String(location),
		}

		name := b.Cluster.ObjectMeta.Name + "-addons-" + key
		manifestPath := "addons/" + *a.Manifest

		manifestBytes, err := b.ClusterAddons.ToYAML()
		if err != nil {
			return fmt.Errorf("error serializing addons: %v", err)
		}

		// Trim whitespace
		manifestBytes = []byte(strings.TrimSpace(string(manifestBytes)))

		rawManifest := string(manifestBytes)

		manifestHash, err := utils.HashString(rawManifest)
		if err != nil {
			return fmt.Errorf("error hashing manifest: %v", err)
		}
		a.ManifestHash = manifestHash

		c.AddTask(&fitasks.ManagedFile{
			Contents:  fi.NewBytesResource(manifestBytes),
			Lifecycle: b.Lifecycle,
			Location:  fi.String(manifestPath),
			Name:      fi.String(name),
		})

		addons.Spec.Addons = append(addons.Spec.Addons, a)
	}

	addonsYAML, err := utils.YamlMarshal(addons)
	if err != nil {
		return fmt.Errorf("error serializing addons yaml: %v", err)
	}

	name := b.Cluster.ObjectMeta.Name + "-addons-bootstrap"

	c.AddTask(&fitasks.ManagedFile{
		Contents:  fi.NewBytesResource(addonsYAML),
		Lifecycle: b.Lifecycle,
		Location:  fi.String("addons/bootstrap-channel.yaml"),
		Name:      fi.String(name),
	})

	return nil
}

func (b *BootstrapChannelBuilder) buildAddons(c *fi.ModelBuilderContext) (*channelsapi.Addons, error) {
	addons := &channelsapi.Addons{}
	addons.Kind = "Addons"
	addons.ObjectMeta.Name = "bootstrap"

	{
		key := "kops-controller.addons.k8s.io"
		version := "1.19.0-beta.2"

		{
			location := key + "/k8s-1.16.yaml"
			id := "k8s-1.16"

			addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
				Name:              fi.String(key),
				Version:           fi.String(version),
				Selector:          map[string]string{"k8s-addon": key},
				Manifest:          fi.String(location),
				KubernetesVersion: ">=1.16.0-alpha.0",
				Id:                id,
			})
		}
	}

	if featureflag.PublicJWKS.Enabled() {
		key := "anonymous-issuer-discovery.addons.k8s.io"
		version := "1.19.0-beta.2"

		{
			location := key + "/k8s-1.16.yaml"
			id := "k8s-1.16"

			addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
				Name:              fi.String(key),
				Version:           fi.String(version),
				Selector:          map[string]string{"k8s-addon": key},
				Manifest:          fi.String(location),
				KubernetesVersion: ">=1.16.0-alpha.0",
				Id:                id,
			})
		}
	}

	{
		key := "core.addons.k8s.io"
		version := "1.4.0"
		location := key + "/v" + version + ".yaml"

		addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
			Name:     fi.String(key),
			Version:  fi.String(version),
			Selector: map[string]string{"k8s-addon": key},
			Manifest: fi.String(location),
		})
	}

	// @check if podsecuritypolicies are enabled and if so, push the default kube-system policy
	if b.Cluster.Spec.KubeAPIServer != nil && b.Cluster.Spec.KubeAPIServer.HasAdmissionController("PodSecurityPolicy") {
		key := "podsecuritypolicy.addons.k8s.io"
		version := "0.0.4"

		{
			location := key + "/k8s-1.12.yaml"
			id := "k8s-1.12"

			addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
				Name:     fi.String(key),
				Version:  fi.String(version),
				Selector: map[string]string{"k8s-addon": key},
				Manifest: fi.String(location),
				Id:       id,
			})
		}
	}

	if b.Cluster.Spec.NodeAuthorization != nil {
		{
			key := "node-authorizer.addons.k8s.io"
			version := "v0.0.4-kops.2"

			{
				location := key + "/k8s-1.12.yaml"
				id := "k8s-1.12.yaml"

				addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
					Name:     fi.String(key),
					Version:  fi.String(version),
					Selector: map[string]string{"k8s-addon": key},
					Manifest: fi.String(location),
					Id:       id,
				})
			}
		}
	}

	kubeDNS := b.Cluster.Spec.KubeDNS

	// This checks if the Kubernetes version is greater than or equal to 1.20
	// and makes the default DNS server as CoreDNS if the DNS provider is not specified
	// and the Kubernetes version is >=1.19
	if kubeDNS.Provider == "" {
		kubeDNS.Provider = "KubeDNS"
		if b.Cluster.IsKubernetesGTE("1.20") {
			kubeDNS.Provider = "CoreDNS"
		}
	}

	if kubeDNS.Provider == "KubeDNS" {

		{
			key := "kube-dns.addons.k8s.io"
			version := "1.15.13-kops.3"

			{
				location := key + "/k8s-1.12.yaml"
				id := "k8s-1.12"

				addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
					Name:     fi.String(key),
					Version:  fi.String(version),
					Selector: map[string]string{"k8s-addon": key},
					Manifest: fi.String(location),
					Id:       id,
				})
			}
		}
	}

	if kubeDNS.Provider == "CoreDNS" {
		{
			key := "coredns.addons.k8s.io"
			version := "1.7.0-kops.2"

			{
				location := key + "/k8s-1.12.yaml"
				id := "k8s-1.12"

				addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
					Name:     fi.String(key),
					Version:  fi.String(version),
					Selector: map[string]string{"k8s-addon": key},
					Manifest: fi.String(location),
					Id:       id,
				})
			}
		}
	}

	// @check if node authorization or bootstrap tokens are enabled an if so we can forgo applying
	// this manifest. For clusters whom are upgrading from RBAC to Node,RBAC the clusterrolebinding
	// will remain and have to be deleted manually once all the nodes have been upgraded.
	enableRBACAddon := true
	if b.UseKopsControllerForNodeBootstrap() || b.Cluster.Spec.NodeAuthorization != nil {
		enableRBACAddon = false
	}
	if b.Cluster.Spec.KubeAPIServer != nil {
		if b.Cluster.Spec.KubeAPIServer.EnableBootstrapAuthToken != nil && *b.Cluster.Spec.KubeAPIServer.EnableBootstrapAuthToken {
			enableRBACAddon = false
		}
	}

	if enableRBACAddon {
		{
			key := "rbac.addons.k8s.io"
			version := "1.8.0"

			{
				location := key + "/k8s-1.8.yaml"
				id := "k8s-1.8"

				addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
					Name:     fi.String(key),
					Version:  fi.String(version),
					Selector: map[string]string{"k8s-addon": key},
					Manifest: fi.String(location),
					Id:       id,
				})
			}
		}
	}

	// RBAC resources for kube-controller-manager to automatically approve node CSRs
	{
		enableCSRApprover := false
		for _, ig := range b.NodeInstanceGroups() {
			if ig.Spec.ImageFamily != nil && ig.Spec.ImageFamily.Bottlerocket != nil {
				enableCSRApprover = true
				break
			}
		}
		if enableCSRApprover {
			key := "csr-approver.rbac.addons.k8s.io"
			version := "v0.0.1"

			{
				location := key + "/k8s-1.20.yaml"
				id := "k8s-1.20"

				addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
					Name:     fi.String(key),
					Version:  fi.String(version),
					Selector: map[string]string{"k8s-addon": key},
					Manifest: fi.String(location),
					Id:       id,
				})
			}
		}
	}

	{
		// Adding the kubelet-api-admin binding: this is required when switching to webhook authorization on the kubelet
		// docs: https://kubernetes.io/docs/reference/access-authn-authz/rbac/#other-component-roles
		// issue: https://github.com/kubernetes/kops/issues/5176
		key := "kubelet-api.rbac.addons.k8s.io"
		version := "v0.0.1"

		{
			location := key + "/k8s-1.9.yaml"
			id := "k8s-1.9"

			addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
				Name:     fi.String(key),
				Version:  fi.String(version),
				Selector: map[string]string{"k8s-addon": key},
				Manifest: fi.String(location),
				Id:       id,
			})
		}
	}

	{
		key := "limit-range.addons.k8s.io"
		version := "1.5.0"
		location := key + "/v" + version + ".yaml"

		addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
			Name:     fi.String(key),
			Version:  fi.String(version),
			Selector: map[string]string{"k8s-addon": key},
			Manifest: fi.String(location),
		})
	}

	// @check the dns-controller has not been disabled
	externalDNS := b.Cluster.Spec.ExternalDNS
	if externalDNS == nil || !externalDNS.Disable {
		{
			key := "dns-controller.addons.k8s.io"
			version := "1.19.0-beta.2"

			{
				location := key + "/k8s-1.12.yaml"
				id := "k8s-1.12"

				addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
					Name:     fi.String(key),
					Version:  fi.String(version),
					Selector: map[string]string{"k8s-addon": key},
					Manifest: fi.String(location),
					Id:       id,
				})
			}
		}

		// Generate dns-controller ServiceAccount IAM permissions
		if b.UseServiceAccountIAM() {
			serviceAccountRoles := []iam.Subject{&dnscontroller.ServiceAccount{}}
			for _, serviceAccountRole := range serviceAccountRoles {
				iamModelBuilder := &model.IAMModelBuilder{KopsModelContext: b.KopsModelContext, Lifecycle: b.Lifecycle}

				err := iamModelBuilder.BuildServiceAccountRoleTasks(serviceAccountRole, c)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	if featureflag.EnableExternalDNS.Enabled() {
		{
			key := "external-dns.addons.k8s.io"
			version := "0.4.5-kops.1"

			{
				location := key + "/k8s-1.12.yaml"
				id := "k8s-1.12"

				addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
					Name:     fi.String(key),
					Version:  fi.String(version),
					Selector: map[string]string{"k8s-addon": key},
					Manifest: fi.String(location),
					Id:       id,
				})
			}
		}
	}

	// @check if the node-local-dns is enabled
	NodeLocalDNS := b.Cluster.Spec.KubeDNS.NodeLocalDNS
	if kubeDNS.Provider == "CoreDNS" && NodeLocalDNS != nil && fi.BoolValue(NodeLocalDNS.Enabled) {
		{
			key := "nodelocaldns.addons.k8s.io"
			version := "1.18.0"

			{
				location := key + "/k8s-1.12.yaml"
				id := "k8s-1.12"

				addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
					Name:     fi.String(key),
					Version:  fi.String(version),
					Selector: map[string]string{"k8s-addon": key},
					Manifest: fi.String(location),
					Id:       id,
				})
			}
		}
	}

	if b.Cluster.Spec.ClusterAutoscaler != nil && fi.BoolValue(b.Cluster.Spec.ClusterAutoscaler.Enabled) {
		{
			key := "cluster-autoscaler.addons.k8s.io"
			version := "1.19.0"

			{
				location := key + "/k8s-1.15.yaml"
				id := "k8s-1.15"

				addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
					Name:              fi.String(key),
					Version:           fi.String(version),
					Selector:          map[string]string{"k8s-addon": key},
					Manifest:          fi.String(location),
					KubernetesVersion: ">=1.15.0",
					Id:                id,
				})
			}
		}
	}

	if b.Cluster.Spec.MetricsServer != nil && fi.BoolValue(b.Cluster.Spec.MetricsServer.Enabled) {
		{
			key := "metrics-server.addons.k8s.io"
			version := "0.3.7"

			{
				location := key + "/k8s-1.11.yaml"
				id := "k8s-1.11"

				addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
					Name:     fi.String(key),
					Version:  fi.String(version),
					Selector: map[string]string{"k8s-app": "metrics-server"},
					Manifest: fi.String(location),
					Id:       id,
				})
			}
		}
	}

	if b.Cluster.Spec.CertManager != nil && fi.BoolValue(b.Cluster.Spec.CertManager.Enabled) {
		{
			key := "certmanager.io"
			version := "1.1.0"

			{
				location := key + "/k8s-1.16.yaml"
				id := "k8s-1.16"

				addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
					Name:     fi.String(key),
					Version:  fi.String(version),
					Selector: map[string]string{"app.kubernetes.io/name": "cert-manager"},
					Manifest: fi.String(location),
					Id:       id,
				})
			}
		}
	}

	nth := b.Cluster.Spec.NodeTerminationHandler

	if nth != nil && fi.BoolValue(nth.Enabled) {

		key := "node-termination-handler.aws"
		version := "1.7.0"

		{
			location := key + "/k8s-1.11.yaml"
			id := "k8s-1.11"

			addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
				Name:     fi.String(key),
				Version:  fi.String(version),
				Selector: map[string]string{"k8s-addon": key},
				Manifest: fi.String(location),
				Id:       id,
			})
		}
	}

	if kops.CloudProviderID(b.Cluster.Spec.CloudProvider) == kops.CloudProviderAWS {
		key := "storage-aws.addons.k8s.io"
		version := "1.17.0"

		{
			id := "v1.15.0"
			location := key + "/" + id + ".yaml"

			addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
				Name:              fi.String(key),
				Version:           fi.String(version),
				Selector:          map[string]string{"k8s-addon": key},
				Manifest:          fi.String(location),
				KubernetesVersion: ">=1.15.0",
				Id:                id,
			})
		}

		{
			id := "v1.7.0"
			location := key + "/" + id + ".yaml"

			addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
				Name:              fi.String(key),
				Version:           fi.String(version),
				Selector:          map[string]string{"k8s-addon": key},
				Manifest:          fi.String(location),
				KubernetesVersion: "<1.15.0",
				Id:                id,
			})
		}
	}

	if kops.CloudProviderID(b.Cluster.Spec.CloudProvider) == kops.CloudProviderDO {
		key := "digitalocean-cloud-controller.addons.k8s.io"
		version := "1.8.1-kops.1"

		{
			id := "k8s-1.8"
			location := key + "/" + id + ".yaml"

			addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
				Name:     fi.String(key),
				Version:  fi.String(version),
				Selector: map[string]string{"k8s-addon": key},
				Manifest: fi.String(location),
				Id:       id,
			})
		}
	}

	if kops.CloudProviderID(b.Cluster.Spec.CloudProvider) == kops.CloudProviderGCE {
		key := "storage-gce.addons.k8s.io"
		version := "1.7.0"

		{
			id := "v1.7.0"
			location := key + "/" + id + ".yaml"

			addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
				Name:     fi.String(key),
				Version:  fi.String(version),
				Selector: map[string]string{"k8s-addon": key},
				Manifest: fi.String(location),
				Id:       id,
			})
		}
	}

	if featureflag.Spotinst.Enabled() && featureflag.SpotinstController.Enabled() {
		key := "spotinst-kubernetes-cluster-controller.addons.k8s.io"

		{
			id := "v1.9.0"
			location := key + "/" + id + ".yaml"
			version := "1.0.39"

			addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
				Name:     fi.String(key),
				Version:  fi.String(version),
				Selector: map[string]string{"k8s-addon": key},
				Manifest: fi.String(location),
				Id:       id,
			})
		}

		{
			id := "v1.14.0"
			location := key + "/" + id + ".yaml"
			version := "1.0.69"

			addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
				Name:              fi.String(key),
				Version:           fi.String(version),
				Selector:          map[string]string{"k8s-addon": key},
				Manifest:          fi.String(location),
				KubernetesVersion: ">=1.14.0",
				Id:                id,
			})
		}
	}

	// The metadata-proxy daemonset conceals node metadata endpoints in GCE.
	// It will land on nodes labeled cloud.google.com/metadata-proxy-ready=true
	if kops.CloudProviderID(b.Cluster.Spec.CloudProvider) == kops.CloudProviderGCE {
		key := "metadata-proxy.addons.k8s.io"
		version := "0.1.12"

		{
			id := "v0.1.12"
			location := key + "/" + id + ".yaml"

			addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
				Name:     fi.String(key),
				Version:  fi.String(version),
				Selector: map[string]string{"k8s-addon": key},
				Manifest: fi.String(location),
				Id:       id,
			})
		}
	}

	if b.Cluster.Spec.Networking.Kopeio != nil {
		key := "networking.kope.io"
		version := "1.0.20181028-kops.2"

		{
			location := key + "/k8s-1.12.yaml"
			id := "k8s-1.12"

			addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
				Name:     fi.String(key),
				Version:  fi.String(version),
				Selector: networkingSelector(),
				Manifest: fi.String(location),
				Id:       id,
			})
		}
	}

	if b.Cluster.Spec.Networking.Weave != nil {
		key := "networking.weave"
		versions := map[string]string{
			"k8s-1.12": "2.7.0-kops.1",
		}

		{
			location := key + "/k8s-1.12.yaml"
			id := "k8s-1.12"

			addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
				Name:     fi.String(key),
				Version:  fi.String(versions[id]),
				Selector: networkingSelector(),
				Manifest: fi.String(location),
				Id:       id,
			})
		}
	}

	if b.Cluster.Spec.Networking.Flannel != nil {
		key := "networking.flannel"
		versions := map[string]string{
			"k8s-1.12": "0.13.0-kops.1",
		}

		{
			location := key + "/k8s-1.12.yaml"
			id := "k8s-1.12"

			addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
				Name:     fi.String(key),
				Version:  fi.String(versions[id]),
				Selector: networkingSelector(),
				Manifest: fi.String(location),
				Id:       id,
			})
		}
	}

	if b.Cluster.Spec.Networking.Calico != nil {
		key := "networking.projectcalico.org"
		versions := map[string]string{
			"k8s-1.12": "3.9.6-kops.2",
			"k8s-1.16": "3.17.1-kops.1",
		}

		{
			id := "k8s-1.12"
			location := key + "/" + id + ".yaml"

			addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
				Name:              fi.String(key),
				Version:           fi.String(versions[id]),
				Selector:          networkingSelector(),
				Manifest:          fi.String(location),
				KubernetesVersion: "<1.16.0",
				Id:                id,
			})
		}

		{
			id := "k8s-1.16"
			location := key + "/" + id + ".yaml"

			addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
				Name:              fi.String(key),
				Version:           fi.String(versions[id]),
				Selector:          networkingSelector(),
				Manifest:          fi.String(location),
				KubernetesVersion: ">=1.16.0",
				Id:                id,
			})
		}
	}

	if b.Cluster.Spec.Networking.Canal != nil {
		key := "networking.projectcalico.org.canal"
		versions := map[string]string{
			"k8s-1.12": "3.7.5-kops.2",
			"k8s-1.15": "3.12.2-kops.1",
			"k8s-1.16": "3.13.4-kops.2",
		}
		{
			id := "k8s-1.12"
			location := key + "/" + id + ".yaml"

			addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
				Name:              fi.String(key),
				Version:           fi.String(versions[id]),
				Selector:          networkingSelector(),
				Manifest:          fi.String(location),
				KubernetesVersion: "<1.15.0",
				Id:                id,
			})
		}
		{
			id := "k8s-1.15"
			location := key + "/" + id + ".yaml"

			addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
				Name:              fi.String(key),
				Version:           fi.String(versions[id]),
				Selector:          networkingSelector(),
				Manifest:          fi.String(location),
				KubernetesVersion: ">=1.15.0 <1.16.0",
				Id:                id,
			})
		}
		{
			id := "k8s-1.16"
			location := key + "/" + id + ".yaml"

			addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
				Name:              fi.String(key),
				Version:           fi.String(versions[id]),
				Selector:          networkingSelector(),
				Manifest:          fi.String(location),
				KubernetesVersion: ">=1.16.0",
				Id:                id,
			})
		}
	}

	if b.Cluster.Spec.Networking.Kuberouter != nil {
		key := "networking.kuberouter"
		versions := map[string]string{
			"k8s-1.12": "1.1.1-kops.1",
		}

		{
			location := key + "/k8s-1.12.yaml"
			id := "k8s-1.12"

			addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
				Name:     fi.String(key),
				Version:  fi.String(versions[id]),
				Selector: networkingSelector(),
				Manifest: fi.String(location),
				Id:       id,
			})
		}
	}

	if b.Cluster.Spec.Networking.AmazonVPC != nil {
		key := "networking.amazon-vpc-routed-eni"

		versions := map[string]string{
			"k8s-1.12": "1.5.5-kops.1",
			"k8s-1.16": "1.7.8-kops.1",
		}

		{
			id := "k8s-1.12"
			location := key + "/" + id + ".yaml"

			addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
				Name:              fi.String(key),
				Version:           fi.String(versions[id]),
				Selector:          networkingSelector(),
				Manifest:          fi.String(location),
				KubernetesVersion: "<1.16.0",
				Id:                id,
			})
		}

		{
			id := "k8s-1.16"
			location := key + "/" + id + ".yaml"

			addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
				Name:              fi.String(key),
				Version:           fi.String(versions[id]),
				Selector:          networkingSelector(),
				Manifest:          fi.String(location),
				KubernetesVersion: ">=1.16.0",
				Id:                id,
			})
		}
	}

	addCiliumAddon(b, addons)

	authenticationSelector := map[string]string{"role.kubernetes.io/authentication": "1"}

	if b.Cluster.Spec.Authentication != nil {
		if b.Cluster.Spec.Authentication.Kopeio != nil {
			key := "authentication.kope.io"
			version := "1.0.20181028-kops.1"

			{
				location := key + "/k8s-1.12.yaml"
				id := "k8s-1.12"

				addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
					Name:     fi.String(key),
					Version:  fi.String(version),
					Selector: authenticationSelector,
					Manifest: fi.String(location),
					Id:       id,
				})
			}
		}
		if b.Cluster.Spec.Authentication.Aws != nil {
			key := "authentication.aws"
			versions := map[string]string{
				"k8s-1.12": "0.5.1-kops.2",
			}

			{
				location := key + "/k8s-1.12.yaml"
				id := "k8s-1.12"

				addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
					Name:     fi.String(key),
					Version:  fi.String(versions[id]),
					Selector: authenticationSelector,
					Manifest: fi.String(location),
					Id:       id,
				})
			}
		}
	}

	if kops.CloudProviderID(b.Cluster.Spec.CloudProvider) == kops.CloudProviderOpenstack {
		{
			key := "storage-openstack.addons.k8s.io"
			version := "1.18.0-kops.1"

			id := "k8s-1.16"
			location := key + "/" + id + ".yaml"

			addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
				Name:              fi.String(key),
				Version:           fi.String(version),
				Manifest:          fi.String(location),
				Selector:          map[string]string{"k8s-addon": key},
				KubernetesVersion: ">=1.15.0",
				Id:                id,
			})
		}

		if b.Cluster.Spec.ExternalCloudControllerManager != nil {
			// cloudprovider specific out-of-tree controller
			{
				key := "openstack.addons.k8s.io"
				version := "1.13.1-kops.1"

				location := key + "/k8s-1.13.yaml"
				id := "k8s-1.13-ccm"

				addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
					Name:     fi.String(key),
					Version:  fi.String(version),
					Manifest: fi.String(location),
					Selector: map[string]string{"k8s-addon": key},
					Id:       id,
				})
			}
		} else {
			{
				key := "core.addons.k8s.io"
				version := "1.12.1-kops.1"

				location := key + "/k8s-1.12.yaml"
				id := "k8s-1.12-ccm"

				addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
					Name:     fi.String(key),
					Version:  fi.String(version),
					Selector: map[string]string{"k8s-addon": key},
					Manifest: fi.String(location),
					Id:       id,
				})
			}
		}
	}

	if kops.CloudProviderID(b.Cluster.Spec.CloudProvider) == kops.CloudProviderAWS {
		key := "aws-cloud-controller.addons.k8s.io"

		if b.Cluster.Spec.ExternalCloudControllerManager != nil {
			// Version refers to the addon configuration.  The CCM tag is given by
			// the template function AWSCCMTag()
			version := "1.18.0-kops.1"
			{
				id := "k8s-1.18"
				location := key + "/" + id + ".yaml"
				addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
					Name:              fi.String(key),
					Version:           fi.String(version),
					Manifest:          fi.String(location),
					Selector:          map[string]string{"k8s-addon": key},
					KubernetesVersion: ">=1.18.0",
					Id:                id,
				})
			}
		}
	}

	if b.Cluster.Spec.KubeScheduler.UsePolicyConfigMap != nil {
		key := "scheduler.addons.k8s.io"
		version := "1.7.0"
		location := key + "/v" + version + ".yaml"

		addons.Spec.Addons = append(addons.Spec.Addons, &channelsapi.AddonSpec{
			Name:     fi.String(key),
			Version:  fi.String(version),
			Selector: map[string]string{"k8s-addon": key},
			Manifest: fi.String(location),
		})
	}

	return addons, nil
}
