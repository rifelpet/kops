package karpenter

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"k8s.io/kops/pkg/apis/kops"
	"k8s.io/kops/pkg/model"
	"k8s.io/kops/pkg/model/iam"
	"k8s.io/kops/pkg/testutils/golden"
	"sigs.k8s.io/yaml"
)

func TestInstanceGroupToEC2NodeClass_Golden(t *testing.T) {
	testdataDir := filepath.Join("testdata", "nodeclass")
	clusterYaml, err := os.ReadFile(filepath.Join(testdataDir, "cluster.yaml"))
	if err != nil {
		t.Fatalf("reading cluster.yaml: %v", err)
	}
	igYaml, err := os.ReadFile(filepath.Join(testdataDir, "instancegroup.yaml"))
	if err != nil {
		t.Fatalf("reading instancegroup.yaml: %v", err)
	}

	var cluster kops.Cluster
	if err := yaml.Unmarshal(clusterYaml, &cluster); err != nil {
		t.Fatalf("unmarshal cluster: %v", err)
	}
	var ig kops.InstanceGroup
	if err := yaml.Unmarshal(igYaml, &ig); err != nil {
		t.Fatalf("unmarshal instancegroup: %v", err)
	}

	m := &KarpenterModel{
		KopsModelContext: &model.KopsModelContext{
			IAMModelContext: iam.IAMModelContext{
				Cluster: &cluster,
			},
		},
	}

	nodeClass, err := m.InstanceGroupToEC2NodeClass(context.Background(), &ig)
	if err != nil {
		t.Fatalf("InstanceGroupToEC2NodeClass error: %v", err)
	}

	actualYaml, err := yaml.Marshal(nodeClass)
	if err != nil {
		t.Fatalf("marshal EC2NodeClass: %v", err)
	}

	golden.AssertMatchesFile(t, string(actualYaml), filepath.Join(testdataDir, "ec2nodeclass.yaml"))
}
