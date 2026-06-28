# `DeviceFileCertificateInfo`

## What this table answers

Use `DeviceFileCertificateInfo` to answer:

**“Is this file signed, is the signature trusted, who signed it, and should I trust the signer?”**

This table helps validate file legitimacy by reviewing certificate and signature details for endpoint files.

---

## Use this table when

Use `DeviceFileCertificateInfo` when investigating:

* Unsigned executables or DLLs
* Invalid, expired, revoked, or untrusted signatures
* Suspicious files pretending to be legitimate software
* Possible code-signing certificate abuse
* Stolen or compromised signing certificates
* Supply chain concerns
* DLL sideloading where a signed process loads an unsigned or suspicious DLL
* Non-Microsoft signed files in sensitive directories
* Software provenance during forensic review

---

## Kickoff KQL query

Use this as your first-pass query. Fill in whichever artifact you have and leave the others blank.

```kql
let lookback = 7d;
let alertDeviceName = "";
let alertSHA1 = "";
let alertSigner = "";
let alertSignerHash = "";
let alertIssuer = "";
let alertCertificateSerialNumber = "";
let alertIsSigned = "";
let alertIsTrusted = "";

DeviceFileCertificateInfo
| where Timestamp >= ago(lookback)
| where isempty(alertDeviceName) or DeviceName =~ alertDeviceName
| where isempty(alertSHA1) or SHA1 =~ alertSHA1
| where isempty(alertSigner) or Signer contains alertSigner
| where isempty(alertSignerHash) or SignerHash =~ alertSignerHash
| where isempty(alertIssuer) or Issuer contains alertIssuer
| where isempty(alertCertificateSerialNumber) or CertificateSerialNumber =~ alertCertificateSerialNumber
| where isempty(alertIsSigned) or tostring(IsSigned) =~ alertIsSigned
| where isempty(alertIsTrusted) or tostring(IsTrusted) =~ alertIsTrusted
| project-reorder Timestamp, DeviceName, SHA1, IsSigned, IsTrusted, Signer, SignerHash, Issuer, IsRootSignerMicrosoft, CertificateExpirationTime, CertificateCountersignatureTime, SignatureType, CertificateSerialNumber, ReportId
| order by Timestamp desc
| take 200
```

### Incident write-up query

Use this shorter version when pasting KQL into a Sentinel incident comment.

Prioritize `SHA1` when available because it ties the certificate information to a specific file. If `SHA1` is not available, use `Signer`, `SignerHash`, `Issuer`, `CertificateSerialNumber`, or `DeviceName`, depending on what the alert gives you.

```kql
DeviceFileCertificateInfo
| where Timestamp >= ago(7d)
| where SHA1 =~ "<SHA1>"
| project-reorder Timestamp, DeviceName, SHA1, IsSigned, IsTrusted, Signer, SignerHash, Issuer, IsRootSignerMicrosoft, CertificateExpirationTime, CertificateCountersignatureTime, SignatureType, CertificateSerialNumber
| order by Timestamp desc
```

Alternative `where` lines you can swap in:

```kql
| where DeviceName =~ "<device-name>"
| where Signer contains "<signer name>"
| where SignerHash =~ "<signer hash>"
| where Issuer contains "<certificate authority>"
| where CertificateSerialNumber =~ "<serial number>"
| where IsSigned == false
| where IsTrusted == false
| where IsRootSignerMicrosoft == false
```

---

## Key fields

| Field                             | Why it matters                                                                                                                       |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `SHA1`                            | File hash. Use this to correlate the same file across `DeviceProcessEvents`, `DeviceFileEvents`, and other device tables.            |
| `IsSigned`                        | Shows whether the file has a digital signature. Unsigned files are not always malicious, but they deserve closer review.             |
| `IsTrusted`                       | Shows whether Windows trust validation succeeded. `false` can indicate an expired, revoked, invalid, or untrusted certificate chain. |
| `Signer`                          | Shows who signed the file. Useful for spotting unusual, suspicious, or abused signers.                                               |
| `SignerHash`                      | Unique signer identifier. Useful for finding all files signed by the same certificate.                                               |
| `Issuer`                          | Certificate authority that issued the certificate. Useful for certificate trust and source review.                                   |
| `IsRootSignerMicrosoft`           | Helps validate whether the file chains back to Microsoft. A non-Microsoft signer for a file in a system path can be suspicious.      |
| `CertificateExpirationTime`       | Shows when the certificate expires. Expired certificates may require closer review.                                                  |
| `CertificateCountersignatureTime` | Shows when the file was timestamped. Compare against expiration time for anomalies.                                                  |
| `SignatureType`                   | Shows whether the signature is embedded or catalog-based.                                                                            |
| `Timestamp`                       | Shows when certificate verification occurred, not when the file was created or executed.                                             |

---

## Do not use this table for

| What you need                                    | Use this instead                                          |
| ------------------------------------------------ | --------------------------------------------------------- |
| File creation, deletion, rename, or modification | `DeviceFileEvents`                                        |
| Process execution and command lines              | `DeviceProcessEvents`                                     |
| Network connections                              | `DeviceNetworkEvents`                                     |
| DLL or image load activity                       | `DeviceImageLoadEvents`                                   |
| Real-time hash hunting from alerts               | Start with `SHA1` / `SHA256` in the relevant device table |

---

## Pivot next

| Starting point            | Pivot to                                   | Why                                                                    |
| ------------------------- | ------------------------------------------ | ---------------------------------------------------------------------- |
| `SHA1`                    | `DeviceProcessEvents`                      | Check whether the file executed.                                       |
| `SHA1`                    | `DeviceFileEvents`                         | Check where the file was created, modified, or observed.               |
| `SHA1`                    | `DeviceImageLoadEvents`                    | Check whether the file was loaded as a DLL or image.                   |
| `SignerHash`              | `DeviceFileCertificateInfo`                | Find other files signed by the same signer.                            |
| `Signer`                  | `DeviceFileCertificateInfo`                | Hunt for files signed by the same organization or certificate subject. |
| `DeviceName`              | `DeviceProcessEvents` / `DeviceFileEvents` | Build endpoint timeline around the file.                               |
| `CertificateSerialNumber` | `DeviceFileCertificateInfo`                | Track files signed with the same certificate.                          |

---

## Quick triage workflow

1. Start with `SHA1` if the alert gives you a file hash.
2. Check `IsSigned` and `IsTrusted`.
3. Review `Signer`, `SignerHash`, and `Issuer`.
4. Check whether the signer makes sense for the file name and location.
5. Compare `CertificateCountersignatureTime` with `CertificateExpirationTime`.
6. Pivot on `SHA1` to see whether the file executed, was created, or was loaded.
7. Pivot on `SignerHash` or `CertificateSerialNumber` to find other files signed by the same certificate.

---

## Watch for

* `IsSigned == false` on executables, DLLs, scripts, or files in sensitive paths
* `IsTrusted == false`
* Suspicious or unknown signers
* Files signed by unexpected non-Microsoft signers in Windows/system directories
* Expired certificates
* Weird timestamping behavior
* Many suspicious files signed by the same `SignerHash`
* Legitimate-looking software signed by unusual or low-reputation issuers
* Unsigned DLLs associated with signed executables

---

## Mental model

Use `DeviceFileCertificateInfo` when your main question is:

**“Can I trust the signature on this file, and does the signer match what this file claims to be?”**
