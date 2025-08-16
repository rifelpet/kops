package karpenter

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/kops/pkg/apis/kops"
	karpenterv1 "sigs.k8s.io/karpenter/pkg/apis/v1"
)

func (k *KarpenterModel) InstanceGroupToNodePool(ctx context.Context, ig *kops.InstanceGroup) (*karpenterv1.NodePool, error) {
	if ig == nil {
		return nil, nil
	}
	nodePool := &karpenterv1.NodePool{}
	nodePool.SetDefaults(ctx)

	// k.CloudTagsForInstanceGroup(ig)

	nodePool.ObjectMeta = ig.ObjectMeta
	nodePool.Spec = karpenterv1.NodePoolSpec{
		Template: karpenterv1.NodeClaimTemplate{
			ObjectMeta: karpenterv1.ObjectMeta{
				Labels:      ig.ObjectMeta.Labels, // join with cloudlabels
				Annotations: ig.ObjectMeta.Annotations,
			},
			Spec: karpenterv1.NodeClaimTemplateSpec{
				NodeClassRef: &karpenterv1.NodeClassReference{
					Name:  "",
					Kind:  "EC2NodeClass",
					Group: "",
				},
				Taints: nil, //ig.Spec.Taints,
				Requirements: []karpenterv1.NodeSelectorRequirementWithMinValues{
					{
						NodeSelectorRequirement: corev1.NodeSelectorRequirement{
							Key:      "",
							Operator: "",
							Values:   []string{},
						},
					},
				},
				TerminationGracePeriod: &metav1.Duration{
					Duration: 30 * time.Second,
				},
				ExpireAfter: karpenterv1.MustParseNillableDuration("30s"),
			},
		},
		Disruption: karpenterv1.Disruption{
			Budgets: []karpenterv1.Budget{
				{
					Nodes: "1",
				},
			},
		},
	}

	if err := nodePool.RuntimeValidate(ctx); err != nil {
		return nil, fmt.Errorf("validating NodePool %q: %v", ig.Name, err)
	}
	return nodePool, nil
}
