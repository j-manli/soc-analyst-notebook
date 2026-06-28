# `DeviceInfo`

## What this table answers

Use `DeviceInfo` to answer:

**“What is this device, how important is it, who uses it, how exposed is it, and is Defender telemetry healthy?”**

This table gives device inventory and context. It is not mainly an event timeline table.

---

## Use this table when

Use `DeviceInfo` when investigating:

* Device identity and inventory details
* Device OS version, build, and platform
* Whether a device is a server, workstation, mobile device, IoT device, or unknown device
* Whether a device is internet-facing
* Device exposure level or asset value
* Which users are logged on or recently associated with the device
* Whether the Defender sensor is healthy
* Whether the device is onboarded to Defender
* Machine group, site, or tag-based scoping
* Cloud-connected devices in Azure, AWS, GCP, or Azure Arc
* Whether an affected device should be prioritized during incident response

---

## Kickoff KQL query

Use this as your first-pass query. Fill in whichever artifact you have and leave the others blank.

```kql
let lookback = 7d;
let alertDeviceName = "";
let alertDeviceId = "";
let alertAccount = "";
let alertOSPlatform = "";
let alertMachineGroup = "";
let alertPublicIP = "";
let alertDeviceType = "";
let alertAssetValue = "";
let alertExposureLevel = "";
let alertSensorHealthState = "";
let alertOnboardingStatus = "";
let alertIsInternetFacing = "";

DeviceInfo
| where Timestamp >= ago(lookback)
| where isempty(alertDeviceName) or DeviceName =~ alertDeviceName
| where isempty(alertDeviceId) or DeviceId == alertDeviceId
| where isempty(alertAccount) or tostring(LoggedOnUsers) contains alertAccount
| where isempty(alertOSPlatform) or OSPlatform contains alertOSPlatform
| where isempty(alertMachineGroup) or MachineGroup contains alertMachineGroup
| where isempty(alertPublicIP) or PublicIP == alertPublicIP
| where isempty(alertDeviceType) or DeviceType contains alertDeviceType or DeviceCategory contains alertDeviceType
| where isempty(alertAssetValue) or AssetValue =~ alertAssetValue
| where isempty(alertExposureLevel) or ExposureLevel =~ alertExposureLevel
| where isempty(alertSensorHealthState) or SensorHealthState =~ alertSensorHealthState
| where isempty(alertOnboardingStatus) or OnboardingStatus =~ alertOnboardingStatus
| where isempty(alertIsInternetFacing) or tostring(IsInternetFacing) =~ alertIsInternetFacing
| summarize arg_max(Timestamp, *) by DeviceId
| project-reorder Timestamp, DeviceName, DeviceId, LoggedOnUsers, OSPlatform, OSVersion, OSBuild, DeviceType, DeviceCategory, IsInternetFacing, AssetValue, ExposureLevel, SensorHealthState, OnboardingStatus, PublicIP, MachineGroup, Site, IsAzureADJoined, JoinType, CloudPlatforms, DeviceManualTags, DeviceDynamicTags, ReportId
| order by Timestamp desc
| take 200
```

### Incident write-up query

Use this shorter version when pasting KQL into a Sentinel incident comment.

Prioritize `DeviceName` or `DeviceId` when investigating a specific endpoint. Use `LoggedOnUsers` when trying to identify user context. Use `ExposureLevel`, `AssetValue`, `IsInternetFacing`, `SensorHealthState`, or `OnboardingStatus` when documenting risk and visibility.

```kql
DeviceInfo
| where Timestamp >= ago(7d)
| where DeviceName =~ "<device-name>"
| summarize arg_max(Timestamp, *) by DeviceId
| project-reorder Timestamp, DeviceName, DeviceId, LoggedOnUsers, OSPlatform, OSVersion, OSBuild, IsInternetFacing, AssetValue, ExposureLevel, DeviceType, DeviceCategory, IsAzureADJoined, JoinType, MachineGroup, SensorHealthState, OnboardingStatus, PublicIP
| order by Timestamp desc
```
> Returns the latest known device inventory record so we can confirm asset context, logged-on users, OS details, exposure, asset value, and Defender sensor/onboarding health.
> Avoids duplicate/stale device inventory records and focus on the latest device context.

Alternative `where` lines you can swap in:

```kql
| where DeviceId == "<DeviceId>"
| where tostring(LoggedOnUsers) contains "<username or user@domain.com>"
| where PublicIP == "<public IP>"
| where OSPlatform contains "<Windows 10/Windows 11/Linux/macOS>"
| where MachineGroup contains "<machine group>"
| where DeviceType contains "<Server/Workstation>"
| where IsInternetFacing == true
| where AssetValue =~ "<High>"
| where ExposureLevel =~ "<High>"
| where SensorHealthState !~ "Active"
| where OnboardingStatus !~ "Onboarded"
```

---

## Key fields

| Field                                  | Why it matters                                                                               |
| -------------------------------------- | -------------------------------------------------------------------------------------------- |
| `DeviceName`                           | Main device name used to correlate across `Device*` tables.                                  |
| `DeviceId`                             | Unique device identifier. Useful when device names change or duplicates exist.               |
| `LoggedOnUsers`                        | Shows users associated with the device. Helpful for identifying possible impacted accounts.  |
| `OSPlatform` / `OSVersion` / `OSBuild` | Useful for vulnerability scoping and OS-specific investigations.                             |
| `IsInternetFacing`                     | Helps prioritize devices exposed to the internet.                                            |
| `AssetValue`                           | Helps prioritize high-value assets such as critical servers or domain controllers.           |
| `ExposureLevel`                        | Shows vulnerability exposure level. Useful for risk-based triage.                            |
| `DeviceType` / `DeviceCategory`        | Helps identify whether the device is a workstation, server, IoT device, network device, etc. |
| `IsAzureADJoined` / `JoinType`         | Shows Microsoft Entra join status and identity context.                                      |
| `MachineGroup`                         | Helps scope investigation by RBAC group, business unit, or device grouping.                  |
| `SensorHealthState`                    | Shows Defender sensor health. Important for identifying telemetry gaps.                      |
| `OnboardingStatus`                     | Shows whether the device is onboarded to Defender.                                           |
| `PublicIP`                             | External IP used to connect to Defender. Useful for NAT, proxy, or external correlation.     |
| `Timestamp`                            | Shows when the device info record was last updated, not when a security event occurred.      |

---

## Do not use this table for

| What you need                                                 | Use this instead        |
| ------------------------------------------------------------- | ----------------------- |
| Process execution                                             | `DeviceProcessEvents`   |
| File activity                                                 | `DeviceFileEvents`      |
| Network connections                                           | `DeviceNetworkEvents`   |
| Registry changes, scheduled tasks, services, or system events | `DeviceEvents`          |
| Logons and authentication activity                            | `DeviceLogonEvents`     |
| DLL or image loads                                            | `DeviceImageLoadEvents` |

---

## Pivot next

| Starting point                           | Pivot to                                   | Why                                                                                   |
| ---------------------------------------- | ------------------------------------------ | ------------------------------------------------------------------------------------- |
| `DeviceName` / `DeviceId`                | Any `Device*` table                        | Use device identity to investigate process, file, network, logon, or system activity. |
| `LoggedOnUsers`                          | `DeviceLogonEvents`                        | Confirm user logons and session activity.                                             |
| `LoggedOnUsers`                          | `IdentityLogonEvents` / sign-in tables     | Review identity activity for associated users.                                        |
| `PublicIP`                               | `DeviceNetworkEvents` / sign-in tables     | Correlate external IP context.                                                        |
| `MachineGroup`                           | `Device*` tables                           | Scope hunting to a business unit, device group, or location.                          |
| `ExposureLevel` / `AssetValue`           | `Device*` tables                           | Prioritize high-risk or high-value devices during triage.                             |
| `SensorHealthState` / `OnboardingStatus` | Defender portal or device management tools | Investigate telemetry or coverage gaps.                                               |

---

## Quick triage workflow

1. Start with `DeviceName` or `DeviceId`.
2. Confirm the device identity and latest inventory record.
3. Review `LoggedOnUsers` for user context.
4. Check `OSPlatform`, `OSVersion`, and `OSBuild` for vulnerability relevance.
5. Check `DeviceType` and `DeviceCategory` to understand whether it is a workstation, server, or other asset.
6. Review `IsInternetFacing`, `AssetValue`, and `ExposureLevel` to prioritize risk.
7. Check `SensorHealthState` and `OnboardingStatus` to confirm telemetry coverage.
8. Use `MachineGroup`, `Site`, and tags to understand ownership or business context.
9. Pivot to the relevant `Device*` event table for actual activity.

---

## Watch for

* `IsInternetFacing == true` on high-value or vulnerable devices
* `AssetValue == High`
* `ExposureLevel == High`
* `SensorHealthState` not healthy or active
* `OnboardingStatus` not onboarded
* Servers or critical systems with suspicious activity
* Outdated OS versions or builds
* Devices with unexpected public IPs
* Devices in unusual machine groups or locations
* Missing or stale device telemetry
* High-value devices with recent suspicious process, file, network, or logon events

---

## Mental model

Use `DeviceInfo` when your main question is:

**“What is this device, how risky or important is it, who uses it, and can I trust the telemetry I’m seeing?”**
