# AWS VPC CNI Routing Issue on Amazon Linux 2023

## Problem Statement

Pods running on Amazon Linux 2023 nodes with AWS VPC CNI cannot reach the Kubernetes API service IP. CoreDNS, EBS CSI, and other pods fail with connection timeouts to `100.64.0.1:443`.

## Root Cause Analysis

### The Conflict

The AWS VPC CNI on Amazon Linux 2023 has a conflict with **amazon-ec2-net-utils**:

1. **ec2-net-utils** queries IMDS for secondary IPv4 addresses and creates `/run/systemd/network/70-ens5.network.d/ec2net_alias.conf` with `[Address]` entries for ALL secondary IPs on the primary ENI (including IPs that VPC CNI uses for pods)

2. **systemd-networkd** applies these addresses to ens5, which automatically creates entries in the kernel's **local routing table**:
   ```
   local 172.20.200.204 dev ens5 proto kernel scope host src 172.20.200.204
   ```

3. **Policy routing rule 0** (`from all lookup local`) is checked before any other rules, so packets destined for pod IPs are delivered locally instead of being forwarded to veths

4. **Pod connectivity fails** because reply packets (from control plane back to pod) are delivered to the local socket instead of being forwarded to the pod's network namespace via the veth

### Packet Flow Analysis

**Working flow (expected):**
```
Control Plane -> ens5 (In) -> routing decision -> veth (Out) -> Pod
```

**Broken flow (actual):**
```
Control Plane -> ens5 (In) -> local table lookup -> delivered locally (dropped)
```

### Key Evidence

1. **tcpdump shows packets arriving but not being forwarded:**
   ```
   ens5  In  IP 172.20.207.242 > 172.20.200.204: ICMP echo reply
   # No corresponding veth Out entry
   ```

2. **Route lookup shows local delivery:**
   ```bash
   $ ip route get 172.20.200.204
   local 172.20.200.204 dev lo table local src 172.20.200.204
   ```

3. **Local table has pod IPs:**
   ```bash
   $ ip route show table local | grep 172.20.200.204
   local 172.20.200.204 dev ens5 proto kernel scope host src 172.20.200.204
   ```

4. **Removing the local route fixes connectivity:**
   ```bash
   $ sudo ip route del local 172.20.200.204 dev ens5 table local
   $ ip route get 172.20.200.204
   172.20.200.204 dev eni425e4cff192 src 172.20.116.68
   # Now packets are routed to the veth as expected
   ```

## Why Current Kops Mitigation is Incomplete

The existing mitigation in `nodeup/pkg/model/networking/amazon-vpc-routed-eni.go`:

| Mitigation | Status | Issue |
|------------|--------|-------|
| `/etc/udev/rules.d/99-vpc-policy-routes.rules` (empty mask file) | Present | Only prevents future udev triggers; `policy-routes@ens5.service` already started before nodeup ran |
| `/etc/systemd/network/10-vpc-cni-secondary.network` (Unmanaged=yes) | Missing | Only affects ens6+, not ens5 (primary ENI) |
| `/usr/lib/systemd/networkd.conf.d/80-release.conf` (ManageForeignRoutes=no) | Present | Prevents systemd-networkd from removing CNI routes, but doesn't prevent ec2-net-utils from adding IPs |

### The Gap

The current mitigation focuses on:
- Preventing systemd-networkd from managing CNI-added routes/rules
- Making secondary ENIs (ens6+) unmanaged

But it does NOT address:
- The `policy-routes@ens5.service` that runs on boot and creates `ec2net_alias.conf`
- The secondary IPs being added to the primary ENI (ens5)
- The local routing table entries created when IPs are assigned to an interface

## Proposed Fix

### Option 1: Stop policy-routes service/timer and remove alias config (Recommended)

The fix is implemented in `amazon-vpc-routed-eni.go` as a systemd oneshot service that dynamically detects the primary interface and disables ec2-net-utils for it. This handles different interface names (ens5, eth0, etc.) across instance types.

The implementation creates:

1. **A script** (`/opt/kops/bin/disable-ec2-net-utils-policy-routes`) that:
   - Detects the primary interface via the default route
   - Stops and disables `refresh-policy-routes@<iface>.timer`
   - Stops `policy-routes@<iface>.service`
   - Clears the `ec2net_alias.conf` drop-in and reloads networkd

2. **A systemd oneshot service** (`disable-ec2-net-utils-policy-routes.service`) that:
   - Runs the script during nodeup
   - Is enabled to run on boot as a safety net

**Important**: The `refresh-policy-routes@<iface>.timer` must be disabled, not just the service. The timer triggers every minute and will re-add the IPs even if the service is stopped.

### Option 2: Clean up local routes via script

Create a script/service that runs after CNI setup to remove local routes for pod IPs:

```bash
#!/bin/bash
# Remove local routes for IPs that have veth routes in main table
for ip in $(ip route show table local | grep "dev ens5" | grep -v "172.20.*.*/16" | awk '{print $2}'); do
    if ip route show | grep -q "$ip dev eni"; then
        ip route del local $ip dev ens5 table local
    fi
done
```

### Option 3: Configure ec2-net-utils to skip CNI IPs

This would require changes to amazon-ec2-net-utils package or configuration, which is outside kops' control.

## Additional Findings

### rp_filter Interaction

During investigation, martian packet drops were observed due to `rp_filter=2` on veth interfaces. While disabling rp_filter (`rp_filter=0`) removed the martian logs, it did not fix connectivity because the local routing issue is the primary cause.

The VPC CNI sets `AWS_VPC_K8S_CNI_CONFIGURE_RPFILTER=false` which should handle rp_filter configuration, but the interaction with ec2-net-utils complicates this.

### Timing Issue - Observed Boot Sequence

From observing a newly launched node (i-071b47b8d68b4354b), the following timeline was captured:

| Time | Event |
|------|-------|
| 01:54:53 | Kernel boots |
| 01:54:58 | `policy-routes@ens5.service` starts, `systemd-networkd` starts |
| 01:54:59 | ec2net queries IMDS for `local-ipv4s` - **no secondary IPs yet** (VPC CNI hasn't attached them) |
| 01:55:14 | systemd-networkd restarted by kops nodeup |
| 01:56:37 | Kubelet starts |
| 01:56:50 | First veth (`eni59e9f8ca1d7`) created by VPC CNI as pod is scheduled |
| 01:57:37 | `refresh-policy-routes@ens5` timer fires (runs every ~1 minute) |
| 01:57:38 | ec2net queries IMDS for `local-ipv4s` - **finds 11 secondary IPs** added by VPC CNI |
| 01:57:38 | ec2net creates `ec2net_alias.conf` with all secondary IPs, reloads networkd |
| 01:57:38 | systemd-networkd reconfigures ens5, adding secondary IPs → **local routes created** |
| 01:57:40 | Pods start failing probes (ebs-csi-node cannot reach healthz endpoint) |

**Key insight**: The problem is NOT the initial boot. The initial `policy-routes@ens5` run finds no secondary IPs. The problem occurs when:
1. VPC CNI attaches secondary IPs to the ENI (via AWS API)
2. The `refresh-policy-routes@ens5.timer` fires (every ~1 minute)
3. ec2-net-utils sees the new IPs in IMDS and adds them to ens5
4. Local routes are created, breaking pod networking

**Evidence from the node:**
```
# Veth route in main table (created by VPC CNI):
172.20.166.164 dev eni59e9f8ca1d7 scope link

# Local route (created by ec2-net-utils via systemd-networkd):
local 172.20.166.164 dev ens5 proto kernel scope host src 172.20.166.164

# The local table (rule 0) takes precedence over main table (rule 32766)
```

The udev mask file only prevents the initial service start, but the `refresh-policy-routes@ens5.timer` continues to run and poll IMDS for changes.

## Verification Steps

To verify the fix works:

1. Check that the disable service ran successfully:
   ```bash
   systemctl status disable-ec2-net-utils-policy-routes.service
   ```

2. Detect the primary interface and check that the timer/service are stopped:
   ```bash
   PRIMARY_IFACE=$(ip -4 route show default | awk '{print $5}' | head -1)
   systemctl is-active "refresh-policy-routes@${PRIMARY_IFACE}.timer"   # should be inactive
   systemctl is-active "policy-routes@${PRIMARY_IFACE}.service"         # should be inactive
   systemctl is-enabled "refresh-policy-routes@${PRIMARY_IFACE}.timer"  # should be disabled
   ```

3. Check that `ec2net_alias.conf` is empty or contains only comments:
   ```bash
   PRIMARY_IFACE=$(ip -4 route show default | awk '{print $5}' | head -1)
   cat "/run/systemd/network/70-${PRIMARY_IFACE}.network.d/ec2net_alias.conf"
   ```

4. Check that pod IPs are NOT in the local routing table:
   ```bash
   ip route show table local | grep "172.20"  # should only show node's primary IP
   ```

5. Check that pod IPs have veth routes but NOT local routes:
   ```bash
   PRIMARY_IFACE=$(ip -4 route show default | awk '{print $5}' | head -1)
   # Should show veth routes for pod IPs
   ip route show | grep "dev eni"

   # The same IPs should NOT appear in local table (except node's primary IP)
   ip route show table local | grep "dev ${PRIMARY_IFACE}"
   ```

6. Verify pod connectivity:
   ```bash
   kubectl exec -it <pod> -- curl -k https://kubernetes.default.svc
   ```

## References

- [AWS VPC CNI GitHub Issue #3524](https://github.com/aws/amazon-vpc-cni-k8s/issues/3524)
- [amazon-ec2-net-utils GitHub](https://github.com/amazonlinux/amazon-ec2-net-utils)
- Kops VPC CNI configuration: `nodeup/pkg/model/networking/amazon-vpc-routed-eni.go`
