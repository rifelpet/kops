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

package awstasks

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/elbv2"
	"k8s.io/klog/v2"
	"k8s.io/kops/upup/pkg/fi"
	"k8s.io/kops/upup/pkg/fi/cloudup/awsup"
	"k8s.io/kops/upup/pkg/fi/cloudup/cloudformation"
	"k8s.io/kops/upup/pkg/fi/cloudup/terraform"
)

// +kops:fitask
type TargetGroup struct {
	Name      *string
	Lifecycle *fi.Lifecycle
	VPC       *VPC
	Tags      map[string]string
	Port      *int64
	Protocol  *string

	// ARN is the Amazon Resource Name for the Target Group
	ARN *string

	// Shared is set if this is an external LB (one we don't create or own)
	Shared *bool

	HealthyThreshold   *int64
	UnhealthyThreshold *int64
}

var _ fi.CompareWithID = &TargetGroup{}

func (e *TargetGroup) CompareWithID() *string {
	return e.ARN
}

func (e *TargetGroup) Find(c *fi.Context) (*TargetGroup, error) {
	cloud := c.Cloud.(awsup.AWSCloud)

	request := &elbv2.DescribeTargetGroupsInput{}
	if e.ARN != nil {
		request.TargetGroupArns = []*string{e.ARN}
	}
	if e.Name != nil {
		request.Names = []*string{e.Name}
	}

	response, err := cloud.ELBV2().DescribeTargetGroups(request)

	if err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == elbv2.ErrCodeTargetGroupNotFoundException {
			if !fi.BoolValue(e.Shared) {
				return nil, nil
			}
		}
		return nil, fmt.Errorf("error describing targetgroup %s: %v", *e.Name, err)
	}

	if len(response.TargetGroups) > 1 {
		return nil, fmt.Errorf("found %d TargetGroups with ID %q, expected 1", len(response.TargetGroups), fi.StringValue(e.Name))
	} else if len(response.TargetGroups) == 0 {
		return nil, nil
	}

	tg := response.TargetGroups[0]

	actual := &TargetGroup{
		Port:               tg.Port,
		Protocol:           tg.Protocol,
		ARN:                tg.TargetGroupArn,
		HealthyThreshold:   tg.HealthyThresholdCount,
		UnhealthyThreshold: tg.UnhealthyThresholdCount,
		VPC:                &VPC{ID: tg.VpcId},
	}

	tagsResp, err := cloud.ELBV2().DescribeTags(&elbv2.DescribeTagsInput{
		ResourceArns: []*string{tg.TargetGroupArn},
	})
	if err != nil {
		return nil, err
	}
	tags := make(map[string]string)
	for _, tagDesc := range tagsResp.TagDescriptions {
		for _, tag := range tagDesc.Tags {
			tags[fi.StringValue(tag.Key)] = fi.StringValue(tag.Value)
		}
	}
	actual.Tags = tags

	// Prevent spurious changes
	actual.Name = e.Name
	actual.Lifecycle = e.Lifecycle
	actual.Shared = e.Shared

	return actual, nil
}

func FindTargetGroupByName(cloud awsup.AWSCloud, findName string) (*elbv2.TargetGroup, error) {
	klog.V(2).Infof("Listing all TargetGroups for FindTargetGroupByName")

	request := &elbv2.DescribeTargetGroupsInput{
		Names: []*string{aws.String(findName)},
	}
	// ELB DescribeTags has a limit of 20 names, so we set the page size here to 20 also
	request.PageSize = aws.Int64(20)

	resp, err := cloud.ELBV2().DescribeTargetGroups(request)

	if err != nil {
		return nil, fmt.Errorf("error describing TargetGroups: %v", err)
	}
	if len(resp.TargetGroups) == 0 {
		return nil, nil
	}

	if len(resp.TargetGroups) != 1 {
		return nil, fmt.Errorf("Found multiple TargetGroups with Name %q", findName)
	}

	return resp.TargetGroups[0], nil
}

func (e *TargetGroup) Run(c *fi.Context) error {
	return fi.DefaultDeltaRunMethod(e, c)
}

func (_ *TargetGroup) ShouldCreate(a, e, changes *TargetGroup) (bool, error) {
	if fi.BoolValue(e.Shared) {
		return false, nil
	}
	return true, nil
}

func (s *TargetGroup) CheckChanges(a, e, changes *TargetGroup) error {
	return nil
}

func (_ *TargetGroup) RenderAWS(t *awsup.AWSAPITarget, a, e, changes *TargetGroup) error {
	shared := fi.BoolValue(e.Shared)
	if shared {
		return nil
	}

	//You register targets for your Network Load Balancer with a target group. By default, the load balancer sends requests
	//to registered targets using the port and protocol that you specified for the target group. You can override this port
	//when you register each target with the target group.

	if a == nil {
		request := &elbv2.CreateTargetGroupInput{
			Name:                    e.Name,
			Port:                    e.Port,
			Protocol:                e.Protocol,
			VpcId:                   e.VPC.ID,
			HealthyThresholdCount:   e.HealthyThreshold,
			UnhealthyThresholdCount: e.UnhealthyThreshold,
		}

		klog.V(2).Infof("Creating Target Group for NLB")
		response, err := t.Cloud.ELBV2().CreateTargetGroup(request)
		if err != nil {
			return fmt.Errorf("Error creating target group for NLB : %v", err)
		}

		targetGroupArn := *response.TargetGroups[0].TargetGroupArn
		e.ARN = fi.String(targetGroupArn)

		if err := t.AddELBV2Tags(targetGroupArn, e.Tags); err != nil {
			return err
		}
	}
	return nil
}

// pkg/model/awsmodel/autoscalinggroup.go doesn't know the ARN of the API TargetGroup tasks that it passes to the master ASGs,
// it only knows the ARN of external target groups passed through the InstanceGroupSpec.
// We lookup the ARN for TargetGroup tasks that don't have it set in order to attach the LB to the ASG.
//
// This means some TargetGroup tasks have ARN set and others do not.
// When `Find`ing the ASG and recreating the TargetGroup tasks we need them to match how the model creates them,
// but we only know the ARNs, not the task names associated with them.
// This reuslts in spurious changes being reported during subsequent `update cluster` runs because the API TargetGroup task is named differently
// between the kops model and the ASG's `Find`.
//
// To prevent this, we need to update the API TargetGroup tasks in the ASG's TargetGroups list.
// Because we don't know whether any given ARN attached to an ASG is an API TargetGroup task or not,
// we have to find the API TargetGroup task, lookup its ARN, then compare that to the list of attached TargetGroups.
func ReconcileTargetGroups(cloud awsup.AWSCloud, actual []*TargetGroup, expected []*TargetGroup) ([]*TargetGroup, error) {
	var apiTGTask *TargetGroup
	for _, tg := range expected {
		// All external TargetGroups have their Shared field set to true. The API TargetGroups do not.
		// Note that Shared is set by the kops model rather than AWS tags.
		if !fi.BoolValue(tg.Shared) {
			apiTGTask = tg
		}
	}

	reconciled := make([]*TargetGroup, 0)

	if apiTGTask != nil && len(actual) > 0 {
		apiTG, err := FindTargetGroupByName(cloud, fi.StringValue(apiTGTask.Name))
		if err != nil {
			return nil, err
		}
		if apiTG != nil {
			for i := 0; i < len(actual); i++ {
				tg := actual[i]
				if aws.StringValue(apiTG.TargetGroupArn) == aws.StringValue(tg.ARN) {
					reconciled = append(reconciled, apiTGTask)
				} else {
					reconciled = append(reconciled, tg)
				}
			}
		}
	}
	return reconciled, nil
}

type terraformTargetGroup struct {
	Name        string                          `json:"name" cty:"name"`
	Port        int64                           `json:"port" cty:"port"`
	Protocol    string                          `json:"protocol" cty:"protocol"`
	VPCID       terraform.Literal               `json:"vpc_id" cty:"vpc_id"`
	Tags        map[string]string               `json:"tags,omitempty" cty:"tags"`
	HealthCheck terraformTargetGroupHealthCheck `json:"health_check" cty:"health_check"`
}

type terraformTargetGroupHealthCheck struct {
	HealthyThreshold   int64  `json:"healthy_threshold" cty:"healthy_threshold"`
	UnhealthyThreshold int64  `json:"unhealthy_threshold" cty:"unhealthy_threshold"`
	Protocol           string `json:"protocol" cty:"protocol"`
}

func (_ *TargetGroup) RenderTerraform(t *terraform.TerraformTarget, a, e, changes *TargetGroup) error {
	shared := fi.BoolValue(e.Shared)
	if shared {
		return nil
	}

	if e.VPC == nil {
		return fmt.Errorf("Missing VPC task from target group:\n%v\n%v", e, e.VPC)
	}

	tf := &terraformTargetGroup{
		Name:     *e.Name,
		Port:     *e.Port,
		Protocol: *e.Protocol,
		VPCID:    *e.VPC.TerraformLink(),
		Tags:     e.Tags,
		HealthCheck: terraformTargetGroupHealthCheck{
			HealthyThreshold:   *e.HealthyThreshold,
			UnhealthyThreshold: *e.UnhealthyThreshold,
			Protocol:           *e.Protocol,
		},
	}

	return t.RenderResource("aws_lb_target_group", *e.Name, tf)
}

func (e *TargetGroup) TerraformLink(params ...string) *terraform.Literal {
	shared := fi.BoolValue(e.Shared)
	if shared {
		if e.ARN != nil {
			return terraform.LiteralFromStringValue(*e.ARN)
		} else {
			klog.Warningf("ID not set on shared Target Group %v", e)
		}
	}
	return terraform.LiteralProperty("aws_lb_target_group", *e.Name, "id")
}

type cloudformationTargetGroup struct {
	Name     string                  `json:"Name"`
	Port     int64                   `json:"Port"`
	Protocol string                  `json:"Protocol"`
	VPCID    *cloudformation.Literal `json:"VpcId"`
	Tags     []cloudformationTag     `json:"Tags"`

	HealthCheckProtocol string `json:"HealthCheckProtocol"`
	HealthyThreshold    int64  `json:"HealthyThresholdCount"`
	UnhealthyThreshold  int64  `json:"UnhealthyThresholdCount"`
}

func (_ *TargetGroup) RenderCloudformation(t *cloudformation.CloudformationTarget, a, e, changes *TargetGroup) error {
	shared := fi.BoolValue(e.Shared)
	if shared {
		return nil
	}

	cf := &cloudformationTargetGroup{
		Name:                *e.Name,
		Port:                *e.Port,
		Protocol:            *e.Protocol,
		VPCID:               e.VPC.CloudformationLink(),
		Tags:                buildCloudformationTags(e.Tags),
		HealthCheckProtocol: *e.Protocol,
		HealthyThreshold:    *e.HealthyThreshold,
		UnhealthyThreshold:  *e.UnhealthyThreshold,
	}
	return t.RenderResource("AWS::ElasticLoadBalancingV2::TargetGroup", *e.Name, cf)
}

func (e *TargetGroup) CloudformationLink() *cloudformation.Literal {
	shared := fi.BoolValue(e.Shared)
	if shared {
		if e.ARN != nil {
			return cloudformation.LiteralString(*e.ARN)
		} else {
			klog.Warningf("ID not set on shared Target Group: %v", e)
		}
	}

	return cloudformation.Ref("AWS::ElasticLoadBalancingV2::TargetGroup", *e.Name)
}
