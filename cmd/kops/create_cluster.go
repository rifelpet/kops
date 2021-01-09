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

package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog/v2"
	"k8s.io/kops/cmd/kops/util"
	api "k8s.io/kops/pkg/apis/kops"
	"k8s.io/kops/pkg/apis/kops/registry"
	"k8s.io/kops/pkg/apis/kops/validation"
	"k8s.io/kops/pkg/assets"
	"k8s.io/kops/pkg/clusteraddons"
	"k8s.io/kops/pkg/commands"
	"k8s.io/kops/pkg/featureflag"
	"k8s.io/kops/pkg/kubeconfig"
	"k8s.io/kops/pkg/kubemanifest"
	"k8s.io/kops/pkg/model/components"
	"k8s.io/kops/upup/pkg/fi"
	"k8s.io/kops/upup/pkg/fi/cloudup"
	"k8s.io/kops/upup/pkg/fi/utils"
	"k8s.io/kubectl/pkg/util/i18n"
	"k8s.io/kubectl/pkg/util/templates"
)

type CreateClusterOptions struct {
	cloudup.NewClusterOptions
	Yes                  bool
	Target               string
	NodeSize             string
	MasterSize           string
	MasterVolumeSize     int32
	NodeVolumeSize       int32
	ContainerRuntime     string
	OutDir               string
	Image                string
	NodeImage            string
	MasterImage          string
	DisableSubnetTags    bool
	NetworkCIDR          string
	DNSZone              string
	NodeSecurityGroups   []string
	MasterSecurityGroups []string
	AssociatePublicIP    *bool

	// SSHPublicKeys is a map of the SSH public keys we should configure; required on AWS, not required on GCE
	SSHPublicKeys map[string][]byte

	// Overrides allows settings values direct in the spec
	Overrides []string

	// Specify tags for AWS instance groups
	CloudLabels string

	// Specify tenancy (default or dedicated) for masters and nodes
	MasterTenancy string
	NodeTenancy   string

	// Allow custom public master name
	MasterPublicName string

	OpenstackNetworkID string

	// DryRun mode output a cluster manifest of Output type.
	DryRun bool
	// Output type during a DryRun
	Output string

	// AddonPaths specify paths to additional components that we can add to a cluster
	AddonPaths []string
}

func (o *CreateClusterOptions) InitDefaults() {
	o.NewClusterOptions.InitDefaults()

	o.Yes = false
	o.Target = cloudup.TargetDirect

	o.ContainerRuntime = "docker"
}

var (
	createClusterLong = templates.LongDesc(i18n.T(`
	Create a kubernetes cluster using command line flags.
	This command creates cloud based resources such as networks and virtual machines. Once
	the infrastructure is in place Kubernetes is installed on the virtual machines.

	These operations are done in parallel and rely on eventual consistency.
	`))

	createClusterExample = templates.Examples(i18n.T(`
	# Create a cluster in AWS in a single zone.
	kops create cluster --name=k8s-cluster.example.com \
		--state=s3://my-state-store \
		--zones=us-east-1a \
		--node-count=2

	# Create a cluster in AWS with HA masters. This cluster
	# has also been configured for private networking in a kops-managed VPC.
	# The bastion flag is set to create an entrypoint for admins to SSH.
	export KOPS_STATE_STORE="s3://my-state-store"
	export MASTER_SIZE="c5.large"
	export NODE_SIZE="m5.large"
	export ZONES="us-east-1a,us-east-1b,us-east-1c"
	kops create cluster k8s-cluster.example.com \
	    --node-count 3 \
		--zones $ZONES \
		--node-size $NODE_SIZE \
		--master-size $MASTER_SIZE \
		--master-zones $ZONES \
		--networking cilium \
		--topology private \
		--bastion="true" \
		--yes

	# Create a cluster in GCE.
	# Note: GCE support is not GA.
	export KOPS_FEATURE_FLAGS=AlphaAllowGCE
	export KOPS_STATE_STORE="gs://my-state-store"
	export ZONES="us-east1-a,us-east1-b,us-east1-c"
	kops create cluster k8s-cluster.example.com \
		--zones $ZONES \
		--master-zones $ZONES \
		--node-count 3 \
		--yes

	# Generate a cluster spec to apply later.
	# Run the following, then: kops create -f filename.yaml
	kops create cluster --name=k8s-cluster.example.com \
		--state=s3://my-state-store \
		--zones=us-east-1a \
		--node-count=2 \
		--dry-run \
		-oyaml > filename.yaml
	`))

	createClusterShort = i18n.T("Create a Kubernetes cluster.")
)

func NewCmdCreateCluster(f *util.Factory, out io.Writer) *cobra.Command {
	options := &CreateClusterOptions{}
	options.InitDefaults()

	sshPublicKey := ""
	associatePublicIP := false

	cmd := &cobra.Command{
		Use:     "cluster",
		Short:   createClusterShort,
		Long:    createClusterLong,
		Example: createClusterExample,
		Run: func(cmd *cobra.Command, args []string) {
			ctx := context.TODO()

			if cmd.Flag("associate-public-ip").Changed {
				options.AssociatePublicIP = &associatePublicIP
			}

			err := rootCommand.ProcessArgs(args)
			if err != nil {
				exitWithError(err)
				return
			}

			options.ClusterName = rootCommand.clusterName

			if sshPublicKey != "" {
				options.SSHPublicKeys, err = loadSSHPublicKeys(sshPublicKey)
				if err != nil {
					exitWithError(fmt.Errorf("error reading SSH key file %q: %v", sshPublicKey, err))
				}
			}

			err = RunCreateCluster(ctx, f, out, options)
			if err != nil {
				exitWithError(err)
			}
		},
	}

	cmd.Flags().BoolVarP(&options.Yes, "yes", "y", options.Yes, "Specify --yes to immediately create the cluster")
	cmd.Flags().StringVar(&options.Target, "target", options.Target, fmt.Sprintf("Valid targets: %s, %s, %s. Set this flag to %s if you want kOps to generate terraform", cloudup.TargetDirect, cloudup.TargetTerraform, cloudup.TargetCloudformation, cloudup.TargetTerraform))

	// Configuration / state location
	if featureflag.EnableSeparateConfigBase.Enabled() {
		cmd.Flags().StringVar(&options.ConfigBase, "config-base", options.ConfigBase, "A cluster-readable location where we mirror configuration information, separate from the state store.  Allows for a state store that is not accessible from the cluster.")
	}

	cmd.Flags().StringVar(&options.CloudProvider, "cloud", options.CloudProvider, "Cloud provider to use - gce, aws, openstack")

	cmd.Flags().StringSliceVar(&options.Zones, "zones", options.Zones, "Zones in which to run the cluster")
	cmd.Flags().StringSliceVar(&options.MasterZones, "master-zones", options.MasterZones, "Zones in which to run masters (must be an odd number)")

	if featureflag.ClusterAddons.Enabled() {
		cmd.Flags().StringSliceVar(&options.AddonPaths, "add", options.AddonPaths, "Paths to addons we should add to the cluster")
	}

	cmd.Flags().StringVar(&options.KubernetesVersion, "kubernetes-version", options.KubernetesVersion, "Version of kubernetes to run (defaults to version in channel)")

	cmd.Flags().StringVar(&options.ContainerRuntime, "container-runtime", options.ContainerRuntime, "Container runtime to use: containerd, docker")

	cmd.Flags().StringVar(&sshPublicKey, "ssh-public-key", sshPublicKey, "SSH public key to use (defaults to ~/.ssh/id_rsa.pub on AWS)")

	cmd.Flags().Int32Var(&options.MasterCount, "master-count", options.MasterCount, "Set number of masters. Defaults to one master per master-zone")
	cmd.Flags().Int32Var(&options.NodeCount, "node-count", options.NodeCount, "Set total number of nodes. Defaults to one node per zone")

	cmd.Flags().StringVar(&options.Image, "image", options.Image, "Set image for all instances.")
	cmd.Flags().StringVar(&options.NodeImage, "node-image", options.NodeImage, "Set image for nodes. Takes precedence over --image")
	cmd.Flags().StringVar(&options.MasterImage, "master-image", options.MasterImage, "Set image for masters. Takes precedence over --image")

	cmd.Flags().StringVar(&options.NodeSize, "node-size", options.NodeSize, "Set instance size for nodes")
	cmd.Flags().StringVar(&options.MasterSize, "master-size", options.MasterSize, "Set instance size for masters")

	cmd.Flags().Int32Var(&options.MasterVolumeSize, "master-volume-size", options.MasterVolumeSize, "Set instance volume size (in GB) for masters")
	cmd.Flags().Int32Var(&options.NodeVolumeSize, "node-volume-size", options.NodeVolumeSize, "Set instance volume size (in GB) for nodes")

	cmd.Flags().StringVar(&options.NetworkID, "vpc", options.NetworkID, "Set to use a shared VPC")
	cmd.Flags().StringSliceVar(&options.SubnetIDs, "subnets", options.SubnetIDs, "Set to use shared subnets")
	cmd.Flags().StringSliceVar(&options.UtilitySubnetIDs, "utility-subnets", options.UtilitySubnetIDs, "Set to use shared utility subnets")
	cmd.Flags().StringVar(&options.NetworkCIDR, "network-cidr", options.NetworkCIDR, "Set to override the default network CIDR")
	cmd.Flags().BoolVar(&options.DisableSubnetTags, "disable-subnet-tags", options.DisableSubnetTags, "Set to disable automatic subnet tagging")

	cmd.Flags().BoolVar(&options.EncryptEtcdStorage, "encrypt-etcd-storage", options.EncryptEtcdStorage, "Generate key in aws kms and use it for encrypt etcd volumes")
	cmd.Flags().StringVar(&options.EtcdStorageType, "etcd-storage-type", options.EtcdStorageType, "The default storage type for etc members")

	cmd.Flags().StringVar(&options.Networking, "networking", options.Networking, "Networking mode to use.  kubenet, external, weave, flannel-vxlan (or flannel), flannel-udp, calico, canal, kube-router, amazonvpc, cilium, cilium-etcd, cni, lyftvpc.")

	cmd.Flags().StringVar(&options.DNSZone, "dns-zone", options.DNSZone, "DNS hosted zone to use (defaults to longest matching zone)")
	cmd.Flags().StringVar(&options.OutDir, "out", options.OutDir, "Path to write any local output")
	cmd.Flags().StringSliceVar(&options.AdminAccess, "admin-access", options.AdminAccess, "Restrict API access to this CIDR.  If not set, access will not be restricted by IP.")
	cmd.Flags().StringSliceVar(&options.SSHAccess, "ssh-access", options.SSHAccess, "Restrict SSH access to this CIDR.  If not set, access will not be restricted by IP. (default [0.0.0.0/0])")

	// TODO: Can we deprecate this flag - it is awkward?
	cmd.Flags().BoolVar(&associatePublicIP, "associate-public-ip", false, "Specify --associate-public-ip=[true|false] to enable/disable association of public IP for master ASG and nodes. Default is 'true'.")

	cmd.Flags().StringSliceVar(&options.NodeSecurityGroups, "node-security-groups", options.NodeSecurityGroups, "Add precreated additional security groups to nodes.")
	cmd.Flags().StringSliceVar(&options.MasterSecurityGroups, "master-security-groups", options.MasterSecurityGroups, "Add precreated additional security groups to masters.")

	cmd.Flags().StringVar(&options.Channel, "channel", options.Channel, "Channel for default versions and configuration to use")

	// Network topology
	cmd.Flags().StringVarP(&options.Topology, "topology", "t", options.Topology, "Controls network topology for the cluster: public|private.")

	// Authorization
	cmd.Flags().StringVar(&options.Authorization, "authorization", options.Authorization, "Authorization mode to use: "+cloudup.AuthorizationFlagAlwaysAllow+" or "+cloudup.AuthorizationFlagRBAC)

	// DNS
	cmd.Flags().StringVar(&options.DNSType, "dns", options.DNSType, "DNS hosted zone to use: public|private.")

	// Bastion
	cmd.Flags().BoolVar(&options.Bastion, "bastion", options.Bastion, "Pass the --bastion flag to enable a bastion instance group. Only applies to private topology.")

	// Allow custom tags from the CLI
	cmd.Flags().StringVar(&options.CloudLabels, "cloud-labels", options.CloudLabels, "A list of KV pairs used to tag all instance groups in AWS (e.g. \"Owner=John Doe,Team=Some Team\").")

	// Master and Node Tenancy
	cmd.Flags().StringVar(&options.MasterTenancy, "master-tenancy", options.MasterTenancy, "The tenancy of the master group on AWS. Can either be default or dedicated.")
	cmd.Flags().StringVar(&options.NodeTenancy, "node-tenancy", options.NodeTenancy, "The tenancy of the node group on AWS. Can be either default or dedicated.")

	cmd.Flags().StringVar(&options.APILoadBalancerClass, "api-loadbalancer-class", options.APILoadBalancerClass, "Currently only supported in AWS. Sets the API loadbalancer class to either 'classic' or 'network'")
	cmd.Flags().StringVar(&options.APILoadBalancerType, "api-loadbalancer-type", options.APILoadBalancerType, "Sets the API loadbalancer type to either 'public' or 'internal'")
	cmd.Flags().StringVar(&options.APISSLCertificate, "api-ssl-certificate", options.APISSLCertificate, "Currently only supported in AWS. Sets the ARN of the SSL Certificate to use for the API server loadbalancer.")

	// Allow custom public master name
	cmd.Flags().StringVar(&options.MasterPublicName, "master-public-name", options.MasterPublicName, "Sets the public master public name")

	// DryRun mode that will print YAML or JSON
	cmd.Flags().BoolVar(&options.DryRun, "dry-run", options.DryRun, "If true, only print the object that would be sent, without sending it. This flag can be used to create a cluster YAML or JSON manifest.")
	cmd.Flags().StringVarP(&options.Output, "output", "o", options.Output, "Output format. One of json|yaml. Used with the --dry-run flag.")

	if featureflag.SpecOverrideFlag.Enabled() {
		cmd.Flags().StringSliceVar(&options.Overrides, "override", options.Overrides, "Directly configure values in the spec")
	}

	// GCE flags
	cmd.Flags().StringVar(&options.Project, "project", options.Project, "Project to use (must be set on GCE)")
	cmd.Flags().StringVar(&options.GCEServiceAccount, "gce-service-account", options.GCEServiceAccount, "Service account with which the GCE VM runs. Warning: if not set, VMs will run as default compute service account.")

	if featureflag.Azure.Enabled() {
		cmd.Flags().StringVar(&options.AzureSubscriptionID, "azure-subscription-id", options.AzureSubscriptionID, "Azure subscription where the cluster is created.")
		cmd.Flags().StringVar(&options.AzureTenantID, "azure-tenant-id", options.AzureTenantID, "Azure tenant where the cluster is created.")
		cmd.Flags().StringVar(&options.AzureResourceGroupName, "azure-resource-group-name", options.AzureResourceGroupName, "Azure resource group name where the cluster is created. The resource group will be created if it doesn't already exist. Defaults to the cluster name.")
		cmd.Flags().StringVar(&options.AzureRouteTableName, "azure-route-table-name", options.AzureRouteTableName, "Azure route table name where the cluster is created.")
		cmd.Flags().StringVar(&options.AzureAdminUser, "azure-admin-user", options.AzureAdminUser, "Azure admin user of VM ScaleSet.")
	}

	if featureflag.Spotinst.Enabled() {
		// Spotinst flags
		cmd.Flags().StringVar(&options.SpotinstProduct, "spotinst-product", options.SpotinstProduct, "Set the product description (valid values: Linux/UNIX, Linux/UNIX (Amazon VPC), Windows and Windows (Amazon VPC))")
		cmd.Flags().StringVar(&options.SpotinstOrientation, "spotinst-orientation", options.SpotinstOrientation, "Set the prediction strategy (valid values: balanced, cost, equal-distribution and availability)")
	}

	// Openstack flags
	cmd.Flags().StringVar(&options.OpenstackExternalNet, "os-ext-net", options.OpenstackExternalNet, "The name of the external network to use with the openstack router")
	cmd.Flags().StringVar(&options.OpenstackExternalSubnet, "os-ext-subnet", options.OpenstackExternalSubnet, "The name of the external floating subnet to use with the openstack router")
	cmd.Flags().StringVar(&options.OpenstackLBSubnet, "os-lb-floating-subnet", options.OpenstackLBSubnet, "The name of the external subnet to use with the kubernetes api")
	cmd.Flags().BoolVar(&options.OpenstackStorageIgnoreAZ, "os-kubelet-ignore-az", options.OpenstackStorageIgnoreAZ, "If true kubernetes may attach volumes across availability zones")
	cmd.Flags().BoolVar(&options.OpenstackLBOctavia, "os-octavia", options.OpenstackLBOctavia, "If true octavia loadbalancer api will be used")
	cmd.Flags().StringVar(&options.OpenstackDNSServers, "os-dns-servers", options.OpenstackDNSServers, "comma separated list of DNS Servers which is used in network")
	cmd.Flags().StringVar(&options.OpenstackNetworkID, "os-network", options.OpenstackNetworkID, "The ID of the existing OpenStack network to use")
	return cmd
}

func RunCreateCluster(ctx context.Context, f *util.Factory, out io.Writer, c *CreateClusterOptions) error {
	isDryrun := false
	// direct requires --yes (others do not, because they don't make changes)
	targetName := c.Target
	if c.Target == cloudup.TargetDirect {
		if !c.Yes {
			isDryrun = true
			targetName = cloudup.TargetDryRun
		}
	}
	if c.Target == cloudup.TargetDryRun {
		isDryrun = true
		targetName = cloudup.TargetDryRun
	}

	if c.DryRun && c.Output == "" {
		return fmt.Errorf("unable to execute --dry-run without setting --output")
	}

	// TODO: Reuse rootCommand stateStore logic?

	if c.OutDir == "" {
		if c.Target == cloudup.TargetTerraform {
			c.OutDir = "out/terraform"
		} else if c.Target == cloudup.TargetCloudformation {
			c.OutDir = "out/cloudformation"
		} else {
			c.OutDir = "out"
		}
	}

	clientset, err := f.Clientset()
	if err != nil {
		return err
	}

	if c.ClusterName == "" {
		return fmt.Errorf("--name is required")
	}

	{
		cluster, err := clientset.GetCluster(ctx, c.ClusterName)
		if err != nil {
			if apierrors.IsNotFound(err) {
				cluster = nil
			} else {
				return err
			}
		}

		if cluster != nil {
			return fmt.Errorf("cluster %q already exists; use 'kops update cluster' to apply changes", c.ClusterName)
		}
	}

	if c.OpenstackNetworkID != "" {
		c.NetworkID = c.OpenstackNetworkID
	}
	c.Networking = "cilium"
	clusterResult, err := cloudup.NewCluster(&c.NewClusterOptions, clientset)
	if err != nil {
		return err
	}

	cluster := clusterResult.Cluster
	instanceGroups := clusterResult.InstanceGroups

	var masters []*api.InstanceGroup
	var nodes []*api.InstanceGroup
	for _, ig := range instanceGroups {
		switch ig.Spec.Role {
		case api.InstanceGroupRoleMaster:
			masters = append(masters, ig)
		case api.InstanceGroupRoleNode:
			nodes = append(nodes, ig)
		}
	}

	cloudLabels, err := parseCloudLabels(c.CloudLabels)
	if err != nil {
		return fmt.Errorf("error parsing global cloud labels: %v", err)
	}
	if len(cloudLabels) != 0 {
		cluster.Spec.CloudLabels = cloudLabels
	}

	if c.NodeSize != "" {
		for _, group := range nodes {
			group.Spec.MachineType = c.NodeSize
		}
	}

	if c.Image != "" {
		for _, group := range instanceGroups {
			group.Spec.Image = c.Image
		}
	}
	if c.MasterImage != "" {
		for _, group := range masters {
			group.Spec.Image = c.MasterImage
		}
	}
	// TODO: remove this before the PR is merged. Only using this to test w/ the E2E presubmits
	{
		cluster.Spec.Authentication = &api.AuthenticationSpec{
			Aws: &api.AwsAuthenticationSpec{
				BackendMode: "CRD",
			},
		}
		featureflag.ParseFlags("+Bottlerocket")
		var owner string
		switch os.Getenv("KOPS_REGIONS") {
		case "us-east-1":
			owner = "092701018921"
		case "us-east-2":
			owner = "419346874475"
		case "us-west-1":
			owner = "724952271658"
		case "us-west-2":
			owner = "651937483462"
		case "ap-east-1":
			owner = "040063162771"
		case "ap-south-1":
			owner = "449901457613"
		case "ap-northeast-1":
			owner = "593245189075"
		case "ap-northeast-2":
			owner = "630172235254"
		case "ap-southeast-1":
			owner = "406264879685"
		case "ap-southeast-2":
			owner = "823100568288"
		case "ca-central-1":
			owner = "229026816814"
		case "eu-central-1":
			owner = "149721548608"
		case "eu-west-1":
			owner = "503807174151"
		case "eu-west-2":
			owner = "941016683700"
		case "eu-west-3":
			owner = "296779064547"
		case "eu-north-1":
			owner = "432623269467"
		case "sa-east-1":
			owner = "044060155884"

		default:
			klog.Fatal("unsupported region, try again")
		}
		for _, group := range nodes {
			group.Spec.Image = fmt.Sprintf("%v/bottlerocket-aws-k8s-1.18-x86_64-v1.0.4-cef8dbd2", owner)
			group.Spec.ImageFamily = &api.ImageFamily{
				Bottlerocket: &api.Bottlerocket{},
			}
		}
	}
	if c.AssociatePublicIP != nil {
		for _, group := range instanceGroups {
			group.Spec.AssociatePublicIP = c.AssociatePublicIP
		}
	}

	if c.MasterTenancy != "" {
		for _, group := range masters {
			group.Spec.Tenancy = c.MasterTenancy
		}
	}

	if c.NodeTenancy != "" {
		for _, group := range nodes {
			group.Spec.Tenancy = c.NodeTenancy
		}
	}

	if len(c.NodeSecurityGroups) > 0 {
		for _, group := range nodes {
			group.Spec.AdditionalSecurityGroups = c.NodeSecurityGroups
		}
	}

	if len(c.MasterSecurityGroups) > 0 {
		for _, group := range masters {
			group.Spec.AdditionalSecurityGroups = c.MasterSecurityGroups
		}
	}

	if c.MasterSize != "" {
		for _, group := range masters {
			group.Spec.MachineType = c.MasterSize
		}
	}

	if c.MasterVolumeSize != 0 {
		for _, group := range masters {
			group.Spec.RootVolumeSize = fi.Int32(c.MasterVolumeSize)
		}
	}

	if c.NodeVolumeSize != 0 {
		for _, group := range nodes {
			group.Spec.RootVolumeSize = fi.Int32(c.NodeVolumeSize)
		}
	}

	if c.DNSZone != "" {
		cluster.Spec.DNSZone = c.DNSZone
	}

	if c.ContainerRuntime != "" {
		cluster.Spec.ContainerRuntime = c.ContainerRuntime
	}
	if c.ContainerRuntime == "containerd" && components.UsesKubenet(cluster.Spec.Networking) {
		return fmt.Errorf("--networking with CNI plugin is required for containerd")
	}

	if c.NetworkCIDR != "" {
		cluster.Spec.NetworkCIDR = c.NetworkCIDR
	}

	cluster.Spec.DisableSubnetTags = c.DisableSubnetTags

	if c.MasterPublicName != "" {
		cluster.Spec.MasterPublicName = c.MasterPublicName
	}

	if err := commands.SetClusterFields(c.Overrides, cluster, instanceGroups); err != nil {
		return err
	}

	cloud, err := cloudup.BuildCloud(cluster)
	if err != nil {
		return err
	}

	err = cloudup.PerformAssignments(cluster, cloud)
	if err != nil {
		return fmt.Errorf("error populating configuration: %v", err)
	}

	strict := false
	err = validation.DeepValidate(cluster, instanceGroups, strict, nil)
	if err != nil {
		return err
	}

	assetBuilder := assets.NewAssetBuilder(cluster, "")
	fullCluster, err := cloudup.PopulateClusterSpec(clientset, cluster, cloud, assetBuilder)
	if err != nil {
		return err
	}

	var fullInstanceGroups []*api.InstanceGroup
	for _, group := range instanceGroups {
		fullGroup, err := cloudup.PopulateInstanceGroupSpec(fullCluster, group, cloud, clusterResult.Channel)
		if err != nil {
			return err
		}
		fullGroup.AddInstanceGroupNodeLabel()
		if api.CloudProviderID(cluster.Spec.CloudProvider) == api.CloudProviderGCE {
			fullGroup.Spec.NodeLabels["cloud.google.com/metadata-proxy-ready"] = "true"
		}
		fullInstanceGroups = append(fullInstanceGroups, fullGroup)
	}

	err = validation.DeepValidate(fullCluster, fullInstanceGroups, true, nil)
	if err != nil {
		return err
	}

	if c.DryRun {
		var obj []runtime.Object
		obj = append(obj, cluster)

		for _, group := range fullInstanceGroups {
			// Cluster name is not populated, and we need it
			group.ObjectMeta.Labels = make(map[string]string)
			group.ObjectMeta.Labels[api.LabelClusterName] = cluster.ObjectMeta.Name
			obj = append(obj, group)
		}
		switch c.Output {
		case OutputYaml:
			if err := fullOutputYAML(out, obj...); err != nil {
				return fmt.Errorf("error writing cluster yaml to stdout: %v", err)
			}
			return nil
		case OutputJSON:
			if err := fullOutputJSON(out, obj...); err != nil {
				return fmt.Errorf("error writing cluster json to stdout: %v", err)
			}
			return nil
		default:
			return fmt.Errorf("unsupported output type %q", c.Output)
		}
	}

	var addons kubemanifest.ObjectList
	for _, p := range c.AddonPaths {
		addon, err := clusteraddons.LoadClusterAddon(p)
		if err != nil {
			return fmt.Errorf("error loading cluster addon %s: %v", p, err)
		}
		addons = append(addons, addon.Objects...)
	}

	// Note we perform as much validation as we can, before writing a bad config
	err = registry.CreateClusterConfig(ctx, clientset, cluster, fullInstanceGroups, addons)
	if err != nil {
		return fmt.Errorf("error writing updated configuration: %v", err)
	}

	configBase, err := clientset.ConfigBaseFor(cluster)
	if err != nil {
		return fmt.Errorf("error building ConfigBase for cluster: %v", err)
	}
	err = registry.WriteConfigDeprecated(cluster, configBase.Join(registry.PathClusterCompleted), fullCluster)
	if err != nil {
		return fmt.Errorf("error writing completed cluster spec: %v", err)
	}

	if len(c.SSHPublicKeys) == 0 {
		autoloadSSHPublicKeys := true
		switch c.CloudProvider {
		case "gce":
			// We don't normally use SSH keys on GCE
			autoloadSSHPublicKeys = false
		}

		if autoloadSSHPublicKeys {
			// Load from default location, if found
			sshPublicKeyPath := "~/.ssh/id_rsa.pub"
			c.SSHPublicKeys, err = loadSSHPublicKeys(sshPublicKeyPath)
			if err != nil {
				// Don't wrap file-not-found
				if os.IsNotExist(err) {
					klog.V(2).Infof("ssh key not found at %s", sshPublicKeyPath)
				} else {
					return fmt.Errorf("error reading SSH key file %q: %v", sshPublicKeyPath, err)
				}
			}
		}
	}

	if len(c.SSHPublicKeys) != 0 {
		sshCredentialStore, err := clientset.SSHCredentialStore(cluster)
		if err != nil {
			return err
		}

		for k, data := range c.SSHPublicKeys {
			err = sshCredentialStore.AddSSHPublicKey(k, data)
			if err != nil {
				return fmt.Errorf("error adding SSH public key: %v", err)
			}
		}
	}

	// Can we actually get to this if??
	if targetName != "" {
		if isDryrun {
			fmt.Fprintf(out, "Previewing changes that will be made:\n\n")
		}

		// TODO: Maybe just embed UpdateClusterOptions in CreateClusterOptions?
		updateClusterOptions := &UpdateClusterOptions{}
		updateClusterOptions.InitDefaults()

		updateClusterOptions.Yes = c.Yes
		updateClusterOptions.Target = c.Target
		updateClusterOptions.OutDir = c.OutDir
		updateClusterOptions.admin = kubeconfig.DefaultKubecfgAdminLifetime
		updateClusterOptions.CreateKubecfg = true

		// SSHPublicKey has already been mapped
		updateClusterOptions.SSHPublicKey = ""

		_, err := RunUpdateCluster(ctx, f, cluster.Name, out, updateClusterOptions)
		if err != nil {
			return err
		}

		if isDryrun {
			var sb bytes.Buffer
			fmt.Fprintf(&sb, "\n")
			fmt.Fprintf(&sb, "Cluster configuration has been created.\n")
			fmt.Fprintf(&sb, "\n")
			fmt.Fprintf(&sb, "Suggestions:\n")
			fmt.Fprintf(&sb, " * list clusters with: kops get cluster\n")
			fmt.Fprintf(&sb, " * edit this cluster with: kops edit cluster %s\n", cluster.Name)
			if len(nodes) > 0 {
				fmt.Fprintf(&sb, " * edit your node instance group: kops edit ig --name=%s %s\n", cluster.Name, nodes[0].ObjectMeta.Name)
			}
			if len(masters) > 0 {
				fmt.Fprintf(&sb, " * edit your master instance group: kops edit ig --name=%s %s\n", cluster.Name, masters[0].ObjectMeta.Name)
			}
			fmt.Fprintf(&sb, "\n")
			fmt.Fprintf(&sb, "Finally configure your cluster with: kops update cluster --name %s --yes --admin\n", cluster.Name)
			fmt.Fprintf(&sb, "\n")

			_, err := out.Write(sb.Bytes())
			if err != nil {
				return fmt.Errorf("error writing to output: %v", err)
			}
		}
	}

	return nil
}

// parseCloudLabels takes a CSV list of key=value records and parses them into a map. Nested '='s are supported via
// quoted strings (eg `foo="bar=baz"` parses to map[string]string{"foo":"bar=baz"}. Nested commas are not supported.
func parseCloudLabels(s string) (map[string]string, error) {

	// Replace commas with newlines to allow a single pass with csv.Reader.
	// We can't use csv.Reader for the initial split because it would see each key=value record as a single field
	// and significantly complicates using quoted fields as keys or values.
	records := strings.Replace(s, ",", "\n", -1)

	// Let the CSV library do the heavy-lifting in handling nested ='s
	r := csv.NewReader(strings.NewReader(records))
	r.Comma = '='
	r.FieldsPerRecord = 2
	r.LazyQuotes = false
	r.TrimLeadingSpace = true
	kvPairs, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("One or more key=value pairs are malformed:\n%s\n:%v", records, err)
	}

	m := make(map[string]string, len(kvPairs))
	for _, pair := range kvPairs {
		m[pair[0]] = pair[1]
	}
	return m, nil
}

func loadSSHPublicKeys(sshPublicKey string) (map[string][]byte, error) {
	sshPublicKeys := make(map[string][]byte)
	if sshPublicKey != "" {
		sshPublicKey = utils.ExpandPath(sshPublicKey)
		authorized, err := ioutil.ReadFile(sshPublicKey)
		if err != nil {
			return nil, err
		}
		sshPublicKeys[fi.SecretNameSSHPrimary] = authorized
		klog.Infof("Using SSH public key: %v\n", sshPublicKey)
	}
	return sshPublicKeys, nil
}
