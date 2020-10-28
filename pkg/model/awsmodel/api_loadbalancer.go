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

package awsmodel

import (
	"fmt"
	"sort"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	"k8s.io/kops/pkg/apis/kops"
	"k8s.io/kops/pkg/dns"
	"k8s.io/kops/upup/pkg/fi"
	"k8s.io/kops/upup/pkg/fi/cloudup/awstasks"
)

// LoadBalancerDefaultIdleTimeout is the default idle time for the ELB
const LoadBalancerDefaultIdleTimeout = 5 * time.Minute

// APILoadBalancerBuilder builds a LoadBalancer for accessing the API
type APILoadBalancerBuilder struct {
	*AWSModelContext

	Lifecycle         *fi.Lifecycle
	SecurityLifecycle *fi.Lifecycle
}

var _ fi.ModelBuilder = &APILoadBalancerBuilder{}

// Build is responsible for building the KubeAPI tasks for the aws model
func (b *APILoadBalancerBuilder) Build(c *fi.ModelBuilderContext) error {
	// Configuration where an ELB fronts the API
	if !b.UseLoadBalancerForAPI() {
		return nil
	}

	lbSpec := b.Cluster.Spec.API.LoadBalancer
	if lbSpec == nil {
		// Skipping API ELB creation; not requested in Spec
		return nil
	}

	switch lbSpec.Type {
	case kops.LoadBalancerTypeInternal, kops.LoadBalancerTypePublic:
	// OK

	default:
		return fmt.Errorf("unhandled LoadBalancer type %q", lbSpec.Type)
	}

	// Compute the subnets - only one per zone, and then break ties based on chooseBestSubnetForELB
	var lbSubnets []*awstasks.Subnet
	{
		subnetsByZone := make(map[string][]*kops.ClusterSubnetSpec)
		for i := range b.Cluster.Spec.Subnets {
			subnet := &b.Cluster.Spec.Subnets[i]

			switch subnet.Type {
			case kops.SubnetTypePublic, kops.SubnetTypeUtility:
				if lbSpec.Type != kops.LoadBalancerTypePublic {
					continue
				}

			case kops.SubnetTypePrivate:
				if lbSpec.Type != kops.LoadBalancerTypeInternal {
					continue
				}

			default:
				return fmt.Errorf("subnet %q had unknown type %q", subnet.Name, subnet.Type)
			}

			subnetsByZone[subnet.Zone] = append(subnetsByZone[subnet.Zone], subnet)
		}

		for zone, subnets := range subnetsByZone {
			subnet := b.chooseBestSubnetForELB(zone, subnets)

			lbSubnets = append(lbSubnets, b.LinkToSubnet(subnet))
		}
	}

	var elb *awstasks.LoadBalancer
	var nlb *awstasks.NetworkLoadBalancer
	{
		loadBalancerName := b.GetELBName32("api")

		idleTimeout := LoadBalancerDefaultIdleTimeout
		if lbSpec.IdleTimeoutSeconds != nil {
			idleTimeout = time.Second * time.Duration(*lbSpec.IdleTimeoutSeconds)
		}

		listeners := map[string]*awstasks.LoadBalancerListener{
			"443": {InstancePort: 443},
		}

		nlbListenerPort := "443"
		nlbListeners := map[string]*awstasks.NetworkLoadBalancerListener{
			nlbListenerPort: {InstancePort: 443},
			//DefaultAction:   "forward",
		}

		if lbSpec.SSLCertificate != "" {
			listeners["443"] = &awstasks.LoadBalancerListener{InstancePort: 443, SSLCertificateID: lbSpec.SSLCertificate}
		}

		if lbSpec.SecurityGroupOverride != nil {
			klog.V(1).Infof("WARNING: You are overwriting the Load Balancers, Security Group. When this is done you are responsible for ensure the correct rules!")
		}

		tags := b.CloudTags(loadBalancerName, false)
		for k, v := range b.Cluster.Spec.CloudLabels {
			tags[k] = v
		}
		// Override the returned name to be the expected ELB name
		tags["Name"] = "api." + b.ClusterName()

		nlb = &awstasks.NetworkLoadBalancer{
			Name:      fi.String("api." + b.ClusterName()),
			Lifecycle: b.Lifecycle,

			LoadBalancerName: fi.String(loadBalancerName),
			Subnets:          lbSubnets,
			Listeners:        nlbListeners,

			Tags: tags,
			VPC:  b.LinkToVPC(),
			Type: fi.String("network"),
		}

		elb = &awstasks.LoadBalancer{
			Name:      fi.String("api." + b.ClusterName()),
			Lifecycle: b.Lifecycle,

			LoadBalancerName: fi.String(loadBalancerName),
			SecurityGroups: []*awstasks.SecurityGroup{
				b.LinkToELBSecurityGroup("api"),
			},
			Subnets:   lbSubnets,
			Listeners: listeners,

			// Configure fast-recovery health-checks
			HealthCheck: &awstasks.LoadBalancerHealthCheck{
				Target:             fi.String("SSL:443"),
				Timeout:            fi.Int64(5),
				Interval:           fi.Int64(10),
				HealthyThreshold:   fi.Int64(2),
				UnhealthyThreshold: fi.Int64(2),
			},

			ConnectionSettings: &awstasks.LoadBalancerConnectionSettings{
				IdleTimeout: fi.Int64(int64(idleTimeout.Seconds())),
			},

			Tags: tags,
		}

		if lbSpec.CrossZoneLoadBalancing == nil {
			lbSpec.CrossZoneLoadBalancing = fi.Bool(false)
		}

		elb.CrossZoneLoadBalancing = &awstasks.LoadBalancerCrossZoneLoadBalancing{
			Enabled: lbSpec.CrossZoneLoadBalancing,
		}

		nlb.CrossZoneLoadBalancing = lbSpec.CrossZoneLoadBalancing

		switch lbSpec.Type {
		case kops.LoadBalancerTypeInternal:
			elb.Scheme = fi.String("internal")
			nlb.Scheme = fi.String("internal")
		case kops.LoadBalancerTypePublic:
			elb.Scheme = nil
			nlb.Scheme = nil
		default:
			return fmt.Errorf("unknown load balancer Type: %q", lbSpec.Type)
		}

		if b.APILoadBalancerClass() == kops.LoadBalancerClassClassic {
			c.AddTask(elb)
		} else if b.APILoadBalancerClass() == kops.LoadBalancerClassNetwork {

			targetGroupPort := fi.Int64(443)
			targetGroupName := b.NLBTargetGroupName("api", nlbListenerPort, "443")
			tags := b.CloudTags(targetGroupName, false)

			// Override the returned name to be the expected NLB TG name
			tags["Name"] = targetGroupName

			tg := &awstasks.TargetGroup{
				Name:               fi.String(targetGroupName),
				VPC:                b.LinkToVPC(),
				Tags:               tags,
				Protocol:           fi.String("TCP"),
				Port:               targetGroupPort,
				HealthyThreshold:   fi.Int64(2),
				UnhealthyThreshold: fi.Int64(2),
				Shared:             fi.Bool(false),
			}

			c.AddTask(tg)

			nlb.TargetGroup = tg
			//nlbListeners[nlbListenerPort].TargetGroups = append(nlbListeners[nlbListenerPort].TargetGroups, tg)
			c.AddTask(nlb) //nlb depends on the target group task
		}

	}

	// TODO: figure out if we need to do removeExtraRules
	// TODO: this is referenced in other parts of code, need to figure out how to stop it from being
	// referenced
	// I0412 16:45:28.182976   73951 loader.go:292]   tmpnlbcluster.k8s.local-addons-storage-aws.addons.k8s.io-v1.7.0
	// error building tasks: unexpected error resolving task "LoadBalancer/api.tmpnlbcluster.k8s.local": unable to find task "SecurityGroup/api-elb.tmpnlbcluster.k8s.local", referenced from LoadBalancer/api.tmpnlbcluster.k8s.local:.SecurityGroups[0]
	// Create security group for API ELB
	var lbSG *awstasks.SecurityGroup
	{
		lbSG = &awstasks.SecurityGroup{
			Name:             fi.String(b.ELBSecurityGroupName("api")),
			Lifecycle:        b.SecurityLifecycle,
			Description:      fi.String("Security group for api ELB"),
			RemoveExtraRules: []string{"port=443"},
			VPC:              b.LinkToVPC(),
		}
		lbSG.Tags = b.CloudTags(*lbSG.Name, false)

		if lbSpec.SecurityGroupOverride != nil {
			lbSG.ID = fi.String(*lbSpec.SecurityGroupOverride)
			lbSG.Shared = fi.Bool(true)
		}

		c.AddTask(lbSG)
	}

	// Allow traffic from ELB to egress freely
	if b.APILoadBalancerClass() == kops.LoadBalancerClassClassic {
		t := &awstasks.SecurityGroupRule{
			Name:          fi.String("api-elb-egress"),
			Lifecycle:     b.SecurityLifecycle,
			CIDR:          fi.String("0.0.0.0/0"),
			Egress:        fi.Bool(true),
			SecurityGroup: lbSG,
		}
		c.AddTask(t)
	}

	// Allow traffic into the ELB from KubernetesAPIAccess CIDRs
	if b.APILoadBalancerClass() == kops.LoadBalancerClassClassic {
		for _, cidr := range b.Cluster.Spec.KubernetesAPIAccess {
			t := &awstasks.SecurityGroupRule{
				Name:          fi.String("https-api-elb-" + cidr),
				Lifecycle:     b.SecurityLifecycle,
				CIDR:          fi.String(cidr),
				FromPort:      fi.Int64(443),
				Protocol:      fi.String("tcp"),
				SecurityGroup: lbSG,
				ToPort:        fi.Int64(443),
			}
			c.AddTask(t)

			// Allow ICMP traffic required for PMTU discovery
			c.AddTask(&awstasks.SecurityGroupRule{
				Name:          fi.String("icmp-pmtu-api-elb-" + cidr),
				Lifecycle:     b.SecurityLifecycle,
				CIDR:          fi.String(cidr),
				FromPort:      fi.Int64(3),
				Protocol:      fi.String("icmp"),
				SecurityGroup: lbSG,
				ToPort:        fi.Int64(4),
			})
		}
	}

	masterGroups, err := b.GetSecurityGroups(kops.InstanceGroupRoleMaster)
	if err != nil {
		return err
	}

	if b.APILoadBalancerClass() == kops.LoadBalancerClassNetwork {
		for _, cidr := range b.Cluster.Spec.KubernetesAPIAccess {

			for i, masterGroup := range masterGroups {
				suffix := masterGroup.Suffix
				t := &awstasks.SecurityGroupRule{
					Name:          fi.String(fmt.Sprintf("KubernetesAPIAccess-to-nlb-to-master%s-%s-%d", suffix, cidr, i)),
					Lifecycle:     b.SecurityLifecycle,
					CIDR:          fi.String(cidr),
					FromPort:      fi.Int64(443),
					Protocol:      fi.String("tcp"),
					SecurityGroup: masterGroup.Task,
					ToPort:        fi.Int64(443),
				}
				c.AddTask(t)

				// Allow ICMP traffic required for PMTU discovery
				c.AddTask(&awstasks.SecurityGroupRule{
					Name:          fi.String(fmt.Sprintf("KubernetesAPIAccess-icmp-pmtu-to-nlb-to-api-master%s-%s-%d", suffix, cidr, i)),
					Lifecycle:     b.SecurityLifecycle,
					CIDR:          fi.String(cidr),
					FromPort:      fi.Int64(3),
					Protocol:      fi.String("icmp"),
					SecurityGroup: masterGroup.Task,
					ToPort:        fi.Int64(4),
				})
			}
		}
	}

	// Add precreated additional security groups to the ELB
	if b.APILoadBalancerClass() == kops.LoadBalancerClassClassic {
		for _, id := range b.Cluster.Spec.API.LoadBalancer.AdditionalSecurityGroups {
			t := &awstasks.SecurityGroup{
				Name:      fi.String(id),
				Lifecycle: b.SecurityLifecycle,
				ID:        fi.String(id),
				Shared:    fi.Bool(true),
			}
			if err := c.EnsureTask(t); err != nil {
				return err
			}
			elb.SecurityGroups = append(elb.SecurityGroups, t)
		}
	}

	// Allow HTTPS to the master instances from the ELB
	if b.APILoadBalancerClass() == kops.LoadBalancerClassClassic {
		for _, masterGroup := range masterGroups {
			suffix := masterGroup.Suffix
			c.AddTask(&awstasks.SecurityGroupRule{
				Name:          fi.String(fmt.Sprintf("https-elb-to-master%s", suffix)),
				Lifecycle:     b.SecurityLifecycle,
				FromPort:      fi.Int64(443),
				Protocol:      fi.String("tcp"),
				SecurityGroup: masterGroup.Task,
				SourceGroup:   lbSG,
				ToPort:        fi.Int64(443),
			})
		}
	}

	if b.APILoadBalancerClass() == kops.LoadBalancerClassNetwork {
		//TODO: resarch if the NLB's nodes will have constant IP's.  If so, consider the following as a TODO:
		// Can tighten security by allowing only https access from the private ip's of the eni's associated with the nlb's nodes in each availability zone.
		// Recommended approach is the whole vpc cidr https://docs.aws.amazon.com/elasticloadbalancing/latest/network/target-group-register-targets.html#target-security-groups
		// work around suggested here https://forums.aws.amazon.com/thread.jspa?threadID=263245&start=0&tstart=0
		// https://docs.aws.amazon.com/sdk-for-go/api/aws/arn/
		for i, masterGroup := range masterGroups {
			suffix := masterGroup.Suffix
			c.AddTask(&awstasks.SecurityGroupRule{
				Name:          fi.String(fmt.Sprintf("nlb-health-check-to-master%s-%d", suffix, i)),
				Lifecycle:     b.SecurityLifecycle,
				FromPort:      fi.Int64(443),
				Protocol:      fi.String("tcp"),
				SecurityGroup: masterGroup.Task,
				ToPort:        fi.Int64(443),
				VPC:           b.LinkToVPC(),
			})
		}
	}

	if dns.IsGossipHostname(b.Cluster.Name) || b.UsePrivateDNS() {
		// Ensure the ELB hostname is included in the TLS certificate,
		// if we're not going to use an alias for it
		if b.APILoadBalancerClass() == kops.LoadBalancerClassClassic {
			elb.ForAPIServer = true
		} else if b.APILoadBalancerClass() == kops.LoadBalancerClassNetwork {
			nlb.ForAPIServer = true
		}

	}

	return nil
}

type scoredSubnet struct {
	score  int
	subnet *kops.ClusterSubnetSpec
}

type ByScoreDescending []*scoredSubnet

func (a ByScoreDescending) Len() int      { return len(a) }
func (a ByScoreDescending) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a ByScoreDescending) Less(i, j int) bool {
	if a[i].score != a[j].score {
		// ! to sort highest score first
		return !(a[i].score < a[j].score)
	}
	// Use name to break ties consistently
	return a[i].subnet.Name < a[j].subnet.Name
}

// Choose between subnets in a zone.
// We have already applied the rules to match internal subnets to internal ELBs and vice-versa for public-facing ELBs.
// For internal ELBs: we prefer the master subnets
// For public facing ELBs: we prefer the utility subnets
func (b *APILoadBalancerBuilder) chooseBestSubnetForELB(zone string, subnets []*kops.ClusterSubnetSpec) *kops.ClusterSubnetSpec {
	if len(subnets) == 0 {
		return nil
	}
	if len(subnets) == 1 {
		return subnets[0]
	}

	migSubnets := sets.NewString()
	for _, ig := range b.MasterInstanceGroups() {
		for _, subnet := range ig.Spec.Subnets {
			migSubnets.Insert(subnet)
		}
	}

	var scoredSubnets []*scoredSubnet
	for _, subnet := range subnets {
		score := 0

		if migSubnets.Has(subnet.Name) {
			score += 1
		}

		if subnet.Type == kops.SubnetTypeUtility {
			score += 1
		}

		scoredSubnets = append(scoredSubnets, &scoredSubnet{
			score:  score,
			subnet: subnet,
		})
	}

	sort.Sort(ByScoreDescending(scoredSubnets))

	if scoredSubnets[0].score == scoredSubnets[1].score {
		klog.V(2).Infof("Making arbitrary choice between subnets in zone %q to attach to ELB (%q vs %q)", zone, scoredSubnets[0].subnet.Name, scoredSubnets[1].subnet.Name)
	}

	return scoredSubnets[0].subnet
}
