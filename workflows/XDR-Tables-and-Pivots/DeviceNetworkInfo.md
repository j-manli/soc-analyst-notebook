# `DeviceNetworkInfo`

## What this table answers

Use `DeviceNetworkInfo` to answer:

**"How is this endpoint configured on the network right now (or at the last inventory update)?"**

This table provides a **snapshot of network configuration**, **not live network traffic**.

---

## Use this table when

Use `DeviceNetworkInfo` when investigating:

* Network adapter configuration
* Device IP addresses
* MAC addresses
* DNS server configuration
* Default gateways
* DHCP servers
* VPN or tunnel usage
* Virtual network adapters
* Devices with multiple network interfaces
* Public vs private network profiles
* Network segmentation questions
* Internet-facing interfaces

---

## Kickoff KQL query

Use this as your first-pass query. Fill in whichever artifact you have and leave the others blank.

```kql id="x2m7qn"
let lookback = 7d;
let alertDeviceName = "";
let alertIPAddress = "";
let alertMacAddress = "";
let alertAdapterName = "";
let alertDnsServer = "";
let alertGateway = "";
let alertDhcpServer = "";
let alertTunnelType = "";
let alertAdapterType = "";

DeviceNetworkInfo
| where Timestamp >= ago(lookback)
| where isempty(alertDeviceName) or DeviceName =~ alertDeviceName
| where isempty(alertIPAddress) or tostring(IPAddresses) contains alertIPAddress
| where isempty(alertMacAddress) or MacAddress =~ alertMacAddress
| where isempty(alertAdapterName) or NetworkAdapterName contains alertAdapterName
| where isempty(alertDnsServer) or tostring(DnsAddresses) contains alertDnsServer
| where isempty(alertGateway) or tostring(DefaultGateways) contains alertGateway
| where isempty(alertDhcpServer) or IPv4Dhcp == alertDhcpServer or IPv6Dhcp == alertDhcpServer
| where isempty(alertTunnelType) or TunnelType =~ alertTunnelType
| where isempty(alertAdapterType) or NetworkAdapterType contains alertAdapterType
| summarize arg_max(Timestamp, *) by DeviceId, NetworkAdapterName
| project-reorder Timestamp, DeviceName, NetworkAdapterName, MacAddress, IPAddresses, ConnectedNetworks, DnsAddresses, DefaultGateways, IPv4Dhcp, IPv6Dhcp, TunnelType, NetworkAdapterType, NetworkAdapterStatus, NetworkAdapterVendor, OnboardingStatus
| order by Timestamp desc
```

### Incident write-up query

Use this shorter version when pasting KQL into a Sentinel incident comment.

Prioritize `DeviceName` when validating a host's network configuration. Use `MacAddress`, `IPAddresses`, or `NetworkAdapterName` when investigating a specific interface.

```kql id="m8v4jr"
DeviceNetworkInfo
| where Timestamp >= ago(7d)
| where DeviceName =~ "<device-name>"
| summarize arg_max(Timestamp, *) by DeviceId, NetworkAdapterName
| project-reorder Timestamp, DeviceName, NetworkAdapterName, MacAddress, IPAddresses, ConnectedNetworks, DnsAddresses, DefaultGateways, IPv4Dhcp, IPv6Dhcp, TunnelType, NetworkAdapterType, NetworkAdapterStatus, NetworkAdapterVendor
| order by Timestamp desc
```

Alternative `where` lines you can swap in:

```kql id="z1c6tp"
| where tostring(IPAddresses) contains "<IP address>"
| where MacAddress =~ "<MAC>"
| where NetworkAdapterName contains "<adapter name>"
| where tostring(DnsAddresses) contains "<DNS server>"
| where tostring(DefaultGateways) contains "<gateway>"
| where IPv4Dhcp == "<DHCP server>"
| where TunnelType =~ "<Teredo/PPTP/SSTP/SSH>"
| where NetworkAdapterStatus =~ "<Up/Down>"
```

```kql id="w5k2nb"
// Purpose: Shows the latest network configuration for each adapter so I can validate IPs, adapters, DNS, gateways, DHCP, tunnels, and overall network posture.
```

---

## Key fields

| Field                   | Why it matters                                                                                  |
| ----------------------- | ----------------------------------------------------------------------------------------------- |
| `NetworkAdapterName`    | Identifies the interface. Useful for distinguishing physical NICs from VPN or virtual adapters. |
| `MacAddress`            | Hardware address. Useful for identifying devices and spotting MAC spoofing.                     |
| `IPAddresses`           | Shows every IP assigned to the adapter. Helpful for finding dual-homed systems.                 |
| `ConnectedNetworks`     | Shows network profile information (Domain, Private, Public) and internet connectivity.          |
| `DnsAddresses`          | DNS servers currently configured. Useful for identifying DNS hijacking.                         |
| `DefaultGateways`       | Shows where traffic is routed. Useful for identifying routing changes.                          |
| `IPv4Dhcp` / `IPv6Dhcp` | DHCP server used by the device. Helpful for rogue DHCP investigations.                          |
| `TunnelType`            | Shows VPN or tunneling technologies such as Teredo or SSTP.                                     |
| `NetworkAdapterType`    | Distinguishes Ethernet, wireless, virtual adapters, etc.                                        |
| `NetworkAdapterStatus`  | Shows whether the adapter is active.                                                            |
| `NetworkAdapterVendor`  | Hardware/vendor information. Unusual vendors may indicate virtual adapters or attacker tooling. |
| `Timestamp`             | Shows when this configuration snapshot was recorded—not when network traffic occurred.          |

---

## Do not use this table for

| What you need                            | Use this instead      |
| ---------------------------------------- | --------------------- |
| Live network connections                 | `DeviceNetworkEvents` |
| Process execution                        | `DeviceProcessEvents` |
| Authentication                           | `DeviceLogonEvents`   |
| File activity                            | `DeviceFileEvents`    |
| Registry or system configuration changes | `DeviceEvents`        |

---

## Pivot next

| Starting point      | Pivot to                    | Why                                                  |
| ------------------- | --------------------------- | ---------------------------------------------------- |
| `DeviceName`        | `DeviceNetworkEvents`       | Review live connections from the device.             |
| `IPAddresses`       | `DeviceNetworkEvents`       | Find traffic involving a specific IP.                |
| `MacAddress`        | Network infrastructure logs | Correlate switch, DHCP, NAC, or firewall logs.       |
| `DnsAddresses`      | `DeviceNetworkEvents`       | Review DNS-related traffic or suspicious lookups.    |
| `ConnectedNetworks` | `DeviceInfo`                | Understand device role and business context.         |
| `TunnelType`        | `DeviceNetworkEvents`       | Determine whether the tunnel is actively being used. |

---

## Quick triage workflow

1. Start with `DeviceName`.
2. Confirm the adapter being investigated.
3. Review assigned IP addresses.
4. Verify DNS servers and default gateways.
5. Check for VPN or tunneling technologies.
6. Look for virtual adapters that should not exist.
7. Confirm the network profile (Domain, Private, Public).
8. Pivot to `DeviceNetworkEvents` to investigate actual traffic.

---

## Watch for

* Multiple active network adapters
* Unexpected public IP addresses
* Suspicious DNS servers
* Unknown DHCP servers
* Unexpected gateway changes
* Virtual adapters created by attacker tools
* Teredo, ISATAP, or other unexpected tunnels
* Public network profiles on corporate assets
* Network adapters repeatedly appearing or disappearing
* Multiple private networks connected simultaneously

---

## Mental model

Use `DeviceNetworkInfo` when your main question is:

**"How is this device connected to the network?"**

Use `DeviceNetworkEvents` when your question becomes:

**"What did this device actually communicate with?"**
