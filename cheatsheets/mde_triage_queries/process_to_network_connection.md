Credit to Mehmet Ergene
```
// Setting the parameters to go back in time and use the ago() function
set query_datetimescope_column = "Timestamp";
set query_datetimescope_to = datetime(2023-09-30T16:55:37.2742317Z);
set query_now = datetime(2023-09-30T16:55:37.2742317Z);
// Actual query
let _file_name = "svchost.exe";
let _device_name = "corpgenws08.otrflabs.com";
let _org_prevalence_threshold = 3;
let _first_seen_treshold = 2d;
// First, generate the IP Host lookup table based on hostname
let IPHostLookup = 
    DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where isnotempty(RemoteUrl)
    | extend RemoteIP = replace_string(RemoteIP, "::ffff:", "") // fixing the RemoteIP problem
    | extend RemoteHostName = extract(@'(?:https?:\/\/)?([^\/\?\:#]+)', 1, RemoteUrl) // extracting the hostname only
    | summarize RepresentativeHostName = take_any(RemoteHostName) by RemoteIP
;
DeviceNetworkEvents
| where Timestamp > ago(15d)
| where ActionType startswith "Connection"
| where DeviceName == _device_name
| where InitiatingProcessFileName =~ "svchost.exe"
| where isnotempty(RemoteUrl)
| extend RemoteIP = replace_string(RemoteIP, "::ffff:", "")
| extend RemoteHostName = extract(@'(?:https?:\/\/)?([^\/\?\:#]+)', 1, RemoteUrl)
// fix the missing hostname
| lookup kind=leftouter IPHostLookup on RemoteIP
| extend RemoteHostName = iff(isnotempty(RemoteHostName), RemoteHostName, RepresentativeHostName)
// Get first and last seen and filter based on threshold
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by RemoteHostName, InitiatingProcessFileName
| where FirstSeen > ago(_first_seen_treshold)
// for each hostname, get organizational info
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where ActionType startswith "Connection"
    | where isnotempty(RemoteUrl)
    // same steps for fixing the fields
    | extend RemoteIP = replace_string(RemoteIP, "::ffff:", "")
    | extend RemoteHostName = extract(@'(?:https?:\/\/)?([^\/\?\:#]+)', 1, RemoteUrl)
    | lookup kind=leftouter IPHostLookup on RemoteIP
    | extend RemoteHostName = iff(isnotempty(RemoteHostName), RemoteHostName, RepresentativeHostName)
    // Get Prevalence information 
    | summarize OrgPrevalence = dcount(DeviceId), FirstSeenInOrg = min(Timestamp), arg_max(Timestamp, *) by RemoteHostName
    ) on  RemoteHostName
// filter by organizational prevalence and/or FirstSeenInOrg
| where OrgPrevalence < _org_prevalence_threshold or isnull(OrgPrevalence)
| project-away DeviceId, DeviceName, RemoteHostName1
```
