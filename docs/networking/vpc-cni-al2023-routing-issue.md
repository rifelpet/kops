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

### Option 1: Stop policy-routes service and remove alias config (Recommended)

Add to `amazon-vpc-routed-eni.go` for AL2023:

```go
// Stop and disable policy-routes@ens5 service to prevent ec2-net-utils
// from adding secondary IPs to the primary ENI
c.AddTask(&nodetasks.Service{
    Name:    "policy-routes@ens5.service",
    Running: fi.PtrTo(false),
    Enabled: fi.PtrTo(false),
})

// Remove the ec2net_alias.conf drop-in that adds secondary IPs
c.AddTask(&nodetasks.File{
    Path: "/run/systemd/network/70-ens5.network.d/ec2net_alias.conf",
    Type: nodetasks.FileType_File,
    Mode: fi.PtrTo("0644"),
    Contents: fi.NewStringResource("# Disabled for VPC CNI compatibility\n"),
    OnChangeExecute: [][]string{
        {"networkctl", "reload"},
    },
})
```

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

### Timing Issue

The `policy-routes@ens5.service` is triggered by udev when the network interface comes up, which happens during early boot. By the time nodeup runs to apply kops configuration, the service has already:
1. Queried IMDS for secondary IPs
2. Created the `ec2net_alias.conf` drop-in
3. Triggered systemd-networkd to apply the IPs

The udev mask file only prevents future triggers, not the initial boot trigger.

## Verification Steps

To verify the fix works:

1. Check that `policy-routes@ens5.service` is stopped/disabled:
   ```bash
   systemctl is-active policy-routes@ens5.service  # should be inactive
   ```

2. Check that `ec2net_alias.conf` is empty or contains only comments:
   ```bash
   cat /run/systemd/network/70-ens5.network.d/ec2net_alias.conf
   ```

3. Check that pod IPs are NOT in the local routing table:
   ```bash
   ip route show table local | grep "172.20"  # should only show node's primary IP
   ```

4. Verify pod connectivity:
   ```bash
   kubectl exec -it <pod> -- curl -k https://kubernetes.default.svc
   ```

## References

- [AWS VPC CNI GitHub Issue #3524](https://github.com/aws/amazon-vpc-cni-k8s/issues/3524)
- [amazon-ec2-net-utils GitHub](https://github.com/amazonlinux/amazon-ec2-net-utils)
- Kops VPC CNI configuration: `nodeup/pkg/model/networking/amazon-vpc-routed-eni.go`
