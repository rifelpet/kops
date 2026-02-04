/*
Copyright 2024 The Kubernetes Authors.

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

package networking

import (
	"k8s.io/kops/nodeup/pkg/model"
	"k8s.io/kops/upup/pkg/fi"
	"k8s.io/kops/upup/pkg/fi/nodeup/nodetasks"
	"k8s.io/kops/util/pkg/distributions"
)

// AmazonVPCRoutedENIBuilder writes the Amazon VPC CNI configuration
type AmazonVPCRoutedENIBuilder struct {
	*model.NodeupModelContext
}

var _ fi.NodeupModelBuilder = &AmazonVPCRoutedENIBuilder{}

// Build is responsible for configuring the network cni
func (b *AmazonVPCRoutedENIBuilder) Build(c *fi.NodeupModelBuilderContext) error {
	if b.NodeupConfig.Networking.AmazonVPC == nil {
		return nil
	}

	if b.Distribution == distributions.DistributionAmazonLinux2023 {
		// Mask udev triggers installed by amazon-ec2-net-utils package
		// Create an empty file 99-vpc-policy-routes.rules
		c.AddTask(&nodetasks.File{
			Path:     "/etc/udev/rules.d/99-vpc-policy-routes.rules",
			Contents: fi.NewStringResource(""),
			Type:     nodetasks.FileType_File,
			OnChangeExecute: [][]string{
				{"udevadm", "control", "--reload-rules"},
				{"udevadm", "trigger"},
			},
		})

		// Disable ec2-net-utils policy-routes for the primary ENI to prevent it
		// from adding secondary IPs (used by VPC CNI for pods) to the interface.
		// When secondary IPs are added, the kernel creates local routing table
		// entries that take precedence over VPC CNI's veth routes, causing pod
		// connectivity failures.
		// See: https://github.com/aws/amazon-vpc-cni-k8s/issues/3524
		c.AddTask(b.buildVPCCNIEc2NetUtilsDisableScript())
		c.AddTask(b.buildVPCCNIEc2NetUtilsDisableService())
	}

	if (b.Distribution.IsUbuntu() && b.Distribution.Version() >= 22.04) ||
		b.Distribution == distributions.DistributionAmazonLinux2023 {
		// Make systemd-networkd ignore foreign settings, else it may
		// unexpectedly delete IP rules and routes added by CNI
		contents := `
# Do not clobber any routes or rules added by CNI.
[Network]
ManageForeignRoutes=no
ManageForeignRoutingPolicyRules=no
`
		c.AddTask(&nodetasks.File{
			Path:            "/usr/lib/systemd/networkd.conf.d/80-release.conf",
			Contents:        fi.NewStringResource(contents),
			Type:            nodetasks.FileType_File,
			OnChangeExecute: [][]string{{"systemctl", "restart", "systemd-networkd"}},
		})
	}

	// Running Amazon VPC CNI on Ubuntu 22.04+ requires
	// setting MACAddressPolicy to `none` (ref: https://github.com/aws/amazon-vpc-cni-k8s/issues/2103
	// & https://github.com/aws/amazon-vpc-cni-k8s/issues/2839
	// & https://github.com/kubernetes/kops/issues/16255)
	if b.Distribution.IsUbuntu() && b.Distribution.Version() >= 22.04 {
		contents := `
[Match]
OriginalName=*
[Link]
NamePolicy=keep kernel database onboard slot path
AlternativeNamesPolicy=database onboard slot path
MACAddressPolicy=none
`

		// Copy all the relevant entries and replace the one that contains MACAddressPolicy= with MACAddressPolicy=none
		c.AddTask(&nodetasks.File{
			Path:            "/etc/systemd/network/99-default.link",
			Contents:        fi.NewStringResource(contents),
			Type:            nodetasks.FileType_File,
			OnChangeExecute: [][]string{{"systemctl", "restart", "systemd-networkd"}},
		})

	}

	// Running Amazon VPC CNI on al2023 requires setting Unmanaged to `yes`
	// ref: https://github.com/aws/amazon-vpc-cni-k8s/issues/3524
	if b.Distribution == distributions.DistributionAmazonLinux2023 {
		contents := `
[Match]
Name=ens[6-9]* ens[1-9][0-9]*

[Link]
Unmanaged=yes
`

		c.AddTask(&nodetasks.File{
			Path:            "/etc/systemd/network/10-vpc-cni-secondary.network",
			Contents:        fi.NewStringResource(contents),
			Type:            nodetasks.FileType_File,
			OnChangeExecute: [][]string{{"systemctl", "restart", "systemd-networkd"}},
		})

	}

	// On Ubuntu 24.04+, cloud-init network hotplug is enabled by default
	// (https://github.com/canonical/cloud-init/pull/4799). This causes cloud-init to reconfigure netplan
	// when Amazon VPC CNI attaches ENIs, breaking network functionality.
	// See: https://github.com/kubernetes/kops/issues/17881
	if b.Distribution.IsUbuntu() && b.Distribution.Version() >= 24.04 {
		contents := `# Disable cloud-init network hotplug to prevent interference with Amazon VPC CNI ENI management.
# See: https://github.com/kubernetes/kops/issues/17881
updates:
  network:
    when: [boot-new-instance]
`
		c.AddTask(&nodetasks.File{
			Path:     "/etc/cloud/cloud.cfg.d/99-disable-network-hotplug.cfg",
			Contents: fi.NewStringResource(contents),
			Type:     nodetasks.FileType_File,
		})
	}

	return nil
}

// buildVPCCNIEc2NetUtilsDisableScript creates a script that disables ec2-net-utils
// policy-routes for the primary ENI. The script detects the primary interface
// dynamically to handle different interface names (ens5, eth0, etc.).
func (b *AmazonVPCRoutedENIBuilder) buildVPCCNIEc2NetUtilsDisableScript() *nodetasks.File {
	script := `#!/bin/bash
# Disable ec2-net-utils policy-routes for the primary ENI to prevent VPC CNI conflicts.
# ec2-net-utils adds secondary IPs to the primary interface, which creates local routing
# table entries that break pod connectivity when using AWS VPC CNI.
# See: https://github.com/aws/amazon-vpc-cni-k8s/issues/3524

set -o errexit
set -o nounset
set -o pipefail

# Detect the primary interface (the one with the default route)
PRIMARY_IFACE=$(ip -4 route show default | awk '{print $5}' | head -1)

if [[ -z "${PRIMARY_IFACE}" ]]; then
    echo "ERROR: Could not detect primary interface"
    exit 1
fi

echo "Detected primary interface: ${PRIMARY_IFACE}"

# Stop and disable the refresh timer that periodically queries IMDS for secondary IPs
TIMER_UNIT="refresh-policy-routes@${PRIMARY_IFACE}.timer"
if systemctl is-active --quiet "${TIMER_UNIT}" 2>/dev/null || systemctl is-enabled --quiet "${TIMER_UNIT}" 2>/dev/null; then
    echo "Stopping and disabling ${TIMER_UNIT}"
    systemctl stop "${TIMER_UNIT}" || true
    systemctl disable "${TIMER_UNIT}" || true
fi

# Stop the service itself
SERVICE_UNIT="policy-routes@${PRIMARY_IFACE}.service"
if systemctl is-active --quiet "${SERVICE_UNIT}" 2>/dev/null; then
    echo "Stopping ${SERVICE_UNIT}"
    systemctl stop "${SERVICE_UNIT}" || true
fi

# Clear the ec2net_alias.conf drop-in that adds secondary IPs
# The file is at /run/systemd/network/70-<iface>.network.d/ec2net_alias.conf
ALIAS_CONF="/run/systemd/network/70-${PRIMARY_IFACE}.network.d/ec2net_alias.conf"
ALIAS_DIR=$(dirname "${ALIAS_CONF}")

if [[ -d "${ALIAS_DIR}" ]]; then
    echo "Clearing ${ALIAS_CONF}"
    cat > "${ALIAS_CONF}" << 'EOF'
# Disabled for VPC CNI compatibility
# See: https://github.com/aws/amazon-vpc-cni-k8s/issues/3524
EOF
    # Reload networkd to apply the change and remove secondary IPs from the interface
    networkctl reload || true
fi

echo "ec2-net-utils policy-routes disabled for ${PRIMARY_IFACE}"
`
	return &nodetasks.File{
		Path:     "/opt/kops/bin/disable-ec2-net-utils-policy-routes",
		Contents: fi.NewStringResource(script),
		Type:     nodetasks.FileType_File,
		Mode:     fi.PtrTo("0755"),
	}
}

// buildVPCCNIEc2NetUtilsDisableService creates a systemd oneshot service that
// runs the disable script. This runs during nodeup and is also enabled to run
// on boot to handle the case where ec2-net-utils is triggered before nodeup.
func (b *AmazonVPCRoutedENIBuilder) buildVPCCNIEc2NetUtilsDisableService() *nodetasks.Service {
	manifest := `[Unit]
Description=Disable ec2-net-utils policy-routes for VPC CNI compatibility
After=network-online.target systemd-networkd.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/kops/bin/disable-ec2-net-utils-policy-routes
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
`
	service := &nodetasks.Service{
		Name:       "disable-ec2-net-utils-policy-routes.service",
		Definition: fi.PtrTo(manifest),
	}
	service.InitDefaults()
	return service
}
