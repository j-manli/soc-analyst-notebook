`AADNonInteractiveUserSignInLogs` records authentication performed by applications on a user’s behalf without a fresh authentication prompt, such as refreshing tokens or using an existing sign-in session.

**When and why:** Use it alongside `SigninLogs` when investigating unusual sign-ins, suspected token theft, or continued access after a suspicious event. It helps identify background authentication that an interactive-only search could miss.

**How:** Filter by account and event timeframe, keeping both successes and failures. Compare the application, resource, IP, device context, and outcome with the user’s expected activity. Use `SessionId`, when available, to follow a suspicious session.

**Interpret carefully:** Existing MFA claims are normal and do not establish legitimacy. Successful authentication does not prove emails were read or files downloaded. For confidential clients, the recorded IP can reflect the original token issuance rather than the current refresh request.

``` kql
let TargetUser = "user@contoso.com";
let EventTime = datetime(2026-09-22T12:00:00Z); // Replace with actual UTC event time
AADNonInteractiveUserSignInLogs
| where TimeGenerated between ((EventTime - 1h) .. (EventTime + 1h))
| where UserPrincipalName =~ TargetUser
| extend AuthenticationDetails = todynamic(AuthenticationDetails),
    DeviceDetail = todynamic(DeviceDetail),
    LocationDetails = todynamic(LocationDetails)
| project-reorder CreatedDateTime, UserPrincipalName, ResultType, ResultDescription,
    IPAddress, LocationDetails, AutonomousSystemNumber,
    AppDisplayName, ResourceDisplayName, DeviceDetail, UserAgent,
    AuthenticationProtocol, IncomingTokenType, AuthenticationDetails,
    ConditionalAccessStatus, RiskLevelDuringSignIn, RiskLevelAggregated,
    RiskEventTypes_V2, SessionId, Id
| order by CreatedDateTime asc
```
