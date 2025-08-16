package karpenter

import (
	"context"
	"fmt"
	"strings"
	"time"

	karpenterawsv1 "github.com/aws/karpenter-provider-aws/pkg/apis/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kops/pkg/apis/kops"
	"k8s.io/kops/upup/pkg/fi/cloudup/awsup"
)

func (k *KarpenterModel) InstanceGroupToEC2NodeClass(ctx context.Context, ig *kops.InstanceGroup) (*karpenterawsv1.EC2NodeClass, error) {
	if ig == nil {
		return nil, nil
	}
	nodeClass := &karpenterawsv1.EC2NodeClass{}
	nodeClass.SetDefaults(ctx)

	userdata := "" // TODO

	kubelet, err := awsKubeletConfiguration(ig.Spec.Kubelet)
	if err != nil {
		return nil, fmt.Errorf("error converting kubelet configuration: %w", err)
	}

	subnetSelectors := make([]karpenterawsv1.SubnetSelectorTerm, 0)
	for _, subnetName := range ig.Spec.Subnets {
		for _, subnet := range k.Cluster.Spec.Networking.Subnets {
			if subnet.Name == subnetName {
				if subnet.ID != "" {
					subnetSelectors = append(subnetSelectors, karpenterawsv1.SubnetSelectorTerm{
						ID: subnet.ID,
					})
				} else {
					subnetSelectors = append(subnetSelectors, karpenterawsv1.SubnetSelectorTerm{
						Tags: map[string]string{
							"kubernetes.io/cluster/" + k.ClusterName(): "owned",
							"Name": subnet.Name + "." + k.ClusterName(),
						},
					})
				}
			}
		}
	}

	tags, err := k.CloudTagsForInstanceGroup(ig)
	if err != nil {
		return nil, fmt.Errorf("error getting cloud tags for instance group %q: %w", ig.Name, err)
	}

	bdms := make([]*karpenterawsv1.BlockDeviceMapping, 0)
	for _, volume := range ig.Spec.Volumes {
		size := resource.MustParse(fmt.Sprintf("%dGi", volume.Size))
		bdm := &karpenterawsv1.BlockDeviceMapping{
			EBS: &karpenterawsv1.BlockDevice{
				VolumeSize:          &size,
				DeleteOnTermination: volume.DeleteOnTermination,
				Encrypted:           volume.Encrypted,
				IOPS:                volume.IOPS,
				KMSKeyID:            volume.Key,
				Throughput:          volume.Throughput,
			},
		}
		if volume.Device != "" {
			bdm.DeviceName = &volume.Device
		}
		if volume.Type != "" {
			bdm.EBS.VolumeType = &volume.Type
		}
		bdms = append(bdms, bdm)
	}
	nodeClass.ObjectMeta = ig.ObjectMeta
	nodeClass.Spec = karpenterawsv1.EC2NodeClassSpec{
		SubnetSelectorTerms:      subnetSelectors,
		AssociatePublicIPAddress: ig.Spec.AssociatePublicIP,
		Kubelet:                  kubelet,
		UserData:                 &userdata,
		Tags:                     tags,
		BlockDeviceMappings:      bdms,
		DetailedMonitoring:       ig.Spec.DetailedInstanceMonitoring,
	}

	securityGroups := make([]karpenterawsv1.SecurityGroupSelectorTerm, 0)
	if sg := ig.Spec.SecurityGroupOverride; sg != nil {
		securityGroups = append(securityGroups, karpenterawsv1.SecurityGroupSelectorTerm{
			ID: *sg,
		})
	} else {
		securityGroups = append(securityGroups, karpenterawsv1.SecurityGroupSelectorTerm{
			Name: k.SecurityGroupName(ig.Spec.Role),
		})
		for _, sg := range ig.Spec.AdditionalSecurityGroups {
			securityGroups = append(securityGroups, karpenterawsv1.SecurityGroupSelectorTerm{
				ID: sg,
			})
		}
	}
	nodeClass.Spec.SecurityGroupSelectorTerms = securityGroups

	switch {
	case strings.HasPrefix(ig.Spec.Image, "ssm:"):
		nodeClass.Spec.AMISelectorTerms = []karpenterawsv1.AMISelectorTerm{
			{
				SSMParameter: strings.TrimPrefix(ig.Spec.Image, "ssm:"),
			},
		}
	case strings.HasPrefix(ig.Spec.Image, "ami-"):
		nodeClass.Spec.AMISelectorTerms = []karpenterawsv1.AMISelectorTerm{
			{
				ID: ig.Spec.Image,
			},
		}
	default:
		name, owner, err := awsup.ParseImageNameOwner(ig.Spec.Image)
		if err != nil {
			return nil, fmt.Errorf("error parsing image name %q: %w", ig.Spec.Image, err)
		}
		nodeClass.Spec.AMISelectorTerms = []karpenterawsv1.AMISelectorTerm{
			{
				Name:  name,
				Owner: owner,
			},
		}
	}

	if iam := ig.Spec.IAM; iam != nil {
		nodeClass.Spec.InstanceProfile = iam.Profile
	}

	if imd := ig.Spec.InstanceMetadata; imd != nil {
		nodeClass.Spec.MetadataOptions = &karpenterawsv1.MetadataOptions{
			HTTPPutResponseHopLimit: imd.HTTPPutResponseHopLimit,
			HTTPTokens:              imd.HTTPTokens,
		}
	}

	return nodeClass, nil
}

func awsKubeletConfiguration(ig *kops.KubeletConfigSpec) (*karpenterawsv1.KubeletConfiguration, error) {
	if ig == nil {
		return nil, nil
	}
	kubelet := &karpenterawsv1.KubeletConfiguration{
		MaxPods:                     ig.MaxPods,
		SystemReserved:              ig.SystemReserved,
		KubeReserved:                ig.KubeReserved,
		ImageGCHighThresholdPercent: ig.ImageGCHighThresholdPercent,
		ImageGCLowThresholdPercent:  ig.ImageGCLowThresholdPercent,
		CPUCFSQuota:                 ig.CPUCFSQuota,
	}
	if ig.ClusterDNS != "" {
		kubelet.ClusterDNS = []string{ig.ClusterDNS}
	}
	if ig.EvictionMaxPodGracePeriod != 0 {
		kubelet.EvictionMaxPodGracePeriod = &ig.EvictionMaxPodGracePeriod
	}

	if eh := ig.EvictionHard; eh != nil {
		evictions := strings.Split(*eh, ",")
		kubelet.EvictionHard = make(map[string]string, len(evictions))
		for e := range evictions {
			parts := strings.SplitN(evictions[e], "<", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid evictionHard value %q, expected format signal<value", evictions[e])
			}
			kubelet.EvictionHard[parts[0]] = parts[1]
		}
	}

	if es := ig.EvictionSoft; es != "" {
		evictions := strings.Split(es, ",")
		kubelet.EvictionSoft = make(map[string]string, len(evictions))
		for e := range evictions {
			parts := strings.SplitN(evictions[e], "<", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid evictionSoft value %q, expected format signal<value", evictions[e])
			}
			kubelet.EvictionSoft[parts[0]] = parts[1]
		}
	}

	if gp := ig.EvictionSoftGracePeriod; gp != "" {
		evictions := strings.Split(gp, ",")
		kubelet.EvictionSoftGracePeriod = make(map[string]metav1.Duration, len(evictions))
		for e := range evictions {
			parts := strings.SplitN(evictions[e], "=", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid evictionSoftGracePeriod value %q, expected format signal=value", evictions[e])
			}
			gracePeriod, err := time.ParseDuration(parts[1])
			if err != nil {
				return nil, err
			}
			kubelet.EvictionSoftGracePeriod[parts[0]] = metav1.Duration{
				Duration: gracePeriod,
			}
		}

	}
	return kubelet, nil
}
