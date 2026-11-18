# README – Evidence Collection and Reproduction

## 1. Purpose and Scope

This README documents the PowerShell commands used to investigate the fictional Nordia cybersecurity incident using the supplied evidence files.

All timestamps are UTC. The analysis is based exclusively on the provided files. No external systems were contacted or scanned, and no live DNS lookups were performed.

The original evidence files were kept unchanged. All commands below are intended to run from the directory containing the evidence files.

## 2. Load Evidence Files

```powershell
$auth = Import-Csv .\auth.csv
$acc = Get-Content .\access.log
$dns = Get-Content .\dns.log
$accounts = Import-Csv .\accounts.csv
```

## 3. Evidence Integrity – SHA-256

```powershell
$files = @(
    "access.log",
    "auth.csv",
    "dns.log",
    "accounts.csv"
)

foreach ($file in $files) {
    Get-FileHash ".\$file" -Algorithm SHA256 |
        Select-Object @{Name="File";Expression={$file}}, Algorithm, Hash
}
```

Expected hashes:

| File | SHA-256 |
|---|---|
| access.log | `1239d60f37df02951f2eb3c0735bd915a5f622682c41771d523a6d836c25ec21` |
| auth.csv | `e978bbc3812e97fbe69e203abcbbf14c69fce41455993218d149d98bb3ac4eb7` |
| dns.log | `b36639ccf39af08fd7959a90410b78b1cdd8025bd77e5cc02420787d9ebf8013` |
| accounts.csv | `87a977d2c8a20ad587413f77550af07f054459f778023089c359b702736c0087` |

The calculated hashes matched the reference hashes in the supplied README.

## 4. Authentication Overview

### 4.1 Event Counts

```powershell
$auth | Group-Object event |
    Sort-Object Name |
    Select-Object Name, Count |
    Format-Table -AutoSize
```

Observed counts:

| Event | Count |
|---|---:|
| login_success | 704 |
| login_failure | 1,125 |
| logout | 297 |
| password_reset_requested | 15 |
| account_created | 1 |

### 4.2 Failed Logins by Source IP

```powershell
$auth | Where-Object {
    $_.event -eq 'login_failure'
} | Group-Object src_ip |
    Sort-Object Count -Descending |
    Select-Object Name, Count |
    Format-Table -AutoSize
```

Key results:

- `203.0.113.142`: 740 failures across customer and admin portals.
- `198.51.100.77`: 309 customer failures.
- `10.20.9.50`: 12 failures associated with the internal vulnerability scanner.
- `192.0.2.50`: 12 failures.

### 4.3 Customer Failures from the Two Suspicious IPs

```powershell
$customerFailures = $auth | Where-Object {
    $_.event -eq 'login_failure' -and
    $_.portal -eq 'customer' -and
    $_.src_ip -in @('203.0.113.142','198.51.100.77')
}

"Total customer failures: $($customerFailures.Count)"

"Unique customer usernames: $(
    ($customerFailures |
        Select-Object -ExpandProperty username -Unique).Count
)"

$customerFailures |
    Group-Object src_ip |
    Select-Object Name, Count |
    Format-Table -AutoSize
```

Observed results:

- Total customer failures: 1,038.
- Unique customer usernames: 1,038.
- `203.0.113.142`: 729 customer failures.
- `198.51.100.77`: 309 customer failures.

### 4.4 Admin Failures

```powershell
$staffFailures = $auth | Where-Object {
    $_.event -eq 'login_failure' -and
    $_.portal -eq 'admin' -and
    $_.src_ip -in @('203.0.113.142','198.51.100.77')
}

"Admin failures: $($staffFailures.Count)"

"Unique admin usernames: $(
    ($staffFailures |
        Select-Object -ExpandProperty username -Unique).Count
)"

$staffFailures |
    Select-Object timestamp, username, src_ip, portal |
    Sort-Object timestamp |
    Format-Table -AutoSize
```

Observed result: 11 admin failures involving 11 distinct usernames, all from `203.0.113.142`, between 04:31:31 and 04:37:37 UTC on 11 March 2026.

Combined, the two suspicious IPs generated 1,049 failed authentication attempts:

- 1,038 customer failures across 1,038 distinct usernames.
- 11 admin failures across 11 distinct usernames.

To retrieve the supporting authentication source lines:

```powershell
Select-String -Path .\auth.csv `
    -Pattern '203\.0\.113\.142|198\.51\.100\.77' |
    Select-Object LineNumber, Line
```

## 5. Suspicious Staff Account

### 5.1 Account Snapshot

```powershell
$accounts | Where-Object {
    $_.username -eq 'l.fontaine'
} | Format-List *
```

The 10 March account snapshot identifies `l.fontaine` as:

- Role: `support`
- MFA enabled: `no`
- Last password change: `2023-09-14`
- Usual access: office network (`192.0.2.50`)

The account snapshot predates the incident. Its recorded role must not be assumed to represent the account's permissions throughout the entire incident.

### 5.2 Successful Staff Logins

```powershell
$auth | Where-Object {
    $_.event -eq 'login_success' -and
    $_.username -eq 'l.fontaine'
} | Select-Object timestamp, username, src_ip, portal, detail |
    Sort-Object timestamp |
    Format-Table -AutoSize
```

Observed successful logins:

| Timestamp (UTC) | Source IP | Portal | MFA |
|---|---|---|---|
| 10 Mar 07:41:12 | `192.0.2.50` | admin | none |
| 11 Mar 04:38:21 | `203.0.113.142` | admin | none |
| 11 Mar 07:41:19 | `192.0.2.50` | admin | none |
| 11 Mar 12:16:56 | `203.0.113.142` | admin | none |
| 11 Mar 20:11:28 | `203.0.113.142` | admin | none |
| 12 Mar 07:42:11 | `192.0.2.50` | admin | none |

The login from `203.0.113.142` at 04:38:21 UTC on 11 March followed 11 failed admin authentication attempts from the same source IP.

The successful admin-portal logins and the earlier account snapshot showing a `support` role should be correlated with account and role audit records. The available snapshot alone does not establish when or how the account's permissions may have changed.

## 6. Unexpected Account Creation

```powershell
$auth | Where-Object {
    $_.event -eq 'account_created'
} | Format-List *
```

Observed event:

- Timestamp: `2026-03-11T05:12:52Z`
- Created account: `svc-backup01`
- Actor: `l.fontaine`
- Source IP: `203.0.113.142`
- Portal: `admin`
- Assigned role: `admin`
- Creation method: `admin_ui`

To check subsequent login activity:

```powershell
$auth | Where-Object {
    $_.event -eq 'login_success' -and
    $_.username -eq 'svc-backup01'
} | Select-Object timestamp, username, src_ip, portal, detail |
    Format-Table -AutoSize
```

Observed subsequent login:

- Timestamp: `2026-03-12T14:07:33Z`
- Account: `svc-backup01`
- Source IP: `192.0.2.213`
- Portal: `admin`
- MFA: none

## 7. Customer and Invoice Export Activity

### 7.1 Identify Customer Export Requests

```powershell
$exports = $acc | Where-Object {
    $_ -match 'GET /admin/customers/export\?'
}

"Total export requests: $($exports.Count)"
```

Observed result: 47 customer export requests.

### 7.2 Compare Office and Suspicious Source Activity

```powershell
$exportSummary = foreach ($ip in @(
    '192.0.2.50',
    '203.0.113.142'
)) {
    $rows = $exports | Where-Object {
        $_ -match [regex]::Escape($ip)
    }

    [PSCustomObject]@{
        IP = $ip
        Requests = $rows.Count
        HTTP_200 = @(
            $rows | Where-Object { $_ -match '" 200 ' }
        ).Count
        Response_Bytes = (
            $rows | ForEach-Object {
                if ($_ -match '"\s+\d{3}\s+(\d+)\s') {
                    [int64]$Matches[1]
                }
            } | Measure-Object -Sum
        ).Sum
    }
}

$exportSummary | Format-Table -AutoSize
```

Observed results:

| Source IP | Requests | HTTP 200 | Response bytes |
|---|---:|---:|---:|
| `192.0.2.50` | 9 | 9 | 302,923 |
| `203.0.113.142` | 38 | 38 | 12,100,227 |

### 7.3 Export Page Sizes

```powershell
$exportDetails = foreach ($line in $exports) {
    if ($line -match 'page=(\d+)&size=(\d+).*"\s+(\d{3})\s+(\d+)\s') {
        [PSCustomObject]@{
            Page = [int]$Matches[1]
            Size = [int]$Matches[2]
            Status = [int]$Matches[3]
            Bytes = [int64]$Matches[4]
        }
    }
}

$exportDetails | Group-Object Size | ForEach-Object {
    [PSCustomObject]@{
        PageSize = $_.Name
        Requests = $_.Count
        HTTP_200 = @(
            $_.Group | Where-Object Status -eq 200
        ).Count
        TotalBytes = (
            $_.Group | Measure-Object Bytes -Sum
        ).Sum
    }
} | Format-Table -AutoSize
```

Observed results:

| Page size | Requests | HTTP 200 | Total bytes |
|---|---:|---:|---:|
| 50 | 10 | 10 | 336,823 |
| 500 | 37 | 37 | 12,066,327 |

The 38 suspicious requests from `203.0.113.142` comprised one `size=50` request and 37 `size=500` requests.

The large-page requests covered pages 1–13 and 16–39. Pages 14 and 15 were absent.

The requested page capacity was 18,550 rows (37 × 500 + 50). This is not proof of 18,550 unique customer records or confirmed data exfiltration.

### 7.4 Customer Invoice Downloads – C1 and C2

The following command extracts invoice-download requests associated with the two customer accounts:

```powershell
$invoiceDownloads = Select-String -Path .\access.log `
    -Pattern 'GET /account/invoices/[^ ]+/download'

$invoiceDownloads |
    Where-Object {
        $_.Line -match 'sonia\.moreau@atelier-vega\.example|karim\.haddad@webmail\.example'
    } |
    ForEach-Object {
        if ($_.Line -match '^\S+ - (\S+) \[([^\]]+)\] "GET ([^ ]+) HTTP/[^"]+" (\d{3})') {
            [PSCustomObject]@{
                Account = $Matches[1]
                Timestamp = $Matches[2]
                Endpoint = $Matches[3]
                Status = $Matches[4]
                LineNumber = $_.LineNumber
            }
        }
    } | Format-Table -AutoSize
```

Observed invoice-download requests during the suspicious customer sessions on 11 March 2026:

| Account | Source IP | Successful downloads (HTTP 200) | Denied attempts (HTTP 403) |
|---|---|---:|---:|
| `karim.haddad@webmail.example` (C1) | `203.0.113.142` | 2 | 3 |
| `sonia.moreau@atelier-vega.example` (C2) | `198.51.100.77` | 2 | 0 |

Supporting access-log lines:

| Account | Timestamp (UTC) | HTTP status | Line |
|---|---|---:|---:|
| C2 – Sonia | 11 Mar 02:25:34 | 200 | 3066 |
| C2 – Sonia | 11 Mar 02:25:52 | 200 | 3070 |
| C1 – Karim | 11 Mar 03:28:09 | 200 | 3538 |
| C1 – Karim | 11 Mar 03:28:27 | 200 | 3541 |
| C1 – Karim | 11 Mar 03:28:52 | 403 | 3545 |
| C1 – Karim | 11 Mar 03:29:04 | 403 | 3547 |
| C1 – Karim | 11 Mar 03:29:11 | 403 | 3549 |

These records establish four successful invoice downloads during the two suspicious sessions. The three HTTP 403 responses indicate denied requests, not successful downloads.

The access log also contains invoice activity for these accounts at other times and from other source IPs. That activity should not be conflated with the suspicious sessions on 11 March.

### 7.5 Administrative Invoice Exports

To identify administrative invoice exports:

```powershell
Select-String -Path .\access.log `
    -Pattern 'invoice.*export|export.*invoice' |
    Select-Object LineNumber, Line
```

Observed events:

| Timestamp (UTC) | Account | Source IP | Invoice period | HTTP status | Line |
|---|---|---|---|---:|---:|
| 12 Mar 14:09:51 | `svc-backup01` | `192.0.2.213` | 2026-02 | 200 | 7668 |
| 12 Mar 14:12:30 | `svc-backup01` | `192.0.2.213` | 2026-01 | 200 | 7672 |
| 12 Mar 14:15:12 | `svc-backup01` | `192.0.2.213` | 2025-12 | 200 | 7688 |

These are administrative invoice export requests made by `svc-backup01`. They are separate from the customer invoice downloads described in Section 7.4.

The HTTP 200 responses establish successful HTTP responses for the export requests. They do not independently establish who received the exported files or whether the data was subsequently transferred outside the organization.

### 7.6 C2 Profile Update Request

To retrieve the corresponding access-log entry:

```powershell
$acc[6864]
```

Observed event:

- Timestamp: `12/Mar/2026:10:07:13 +0000`
- Account: `sonia.moreau@atelier-vega.example`
- Source IP: `203.0.113.37`
- Request: `POST /account/profile`
- HTTP status: `302`
- Access-log line: 6865

The log confirms that a profile-update request was submitted. It does not expose the submitted fields or establish exactly what profile data changed.

The source IP differs from the IP used during C2's suspicious login on 11 March (`198.51.100.77`). The event requires correlation with application audit records before its legitimacy can be determined.

## 8. DNS Activity

### 8.1 Webhook DNS Activity

```powershell
$webhookDns = $dns | Where-Object {
    $_ -match 'hooks\.nordia-notify\.example'
}

"Total webhook DNS events: $($webhookDns.Count)"

$webhookDns
```

Observed result: 53 DNS queries.

The queries were made by `10.20.1.10` (`web-01`) for:

`hooks.nordia-notify.example`

The recorded DNS response was:

`A NOERROR 203.0.113.250`

To retrieve the related web access entries:

```powershell
Select-String -Path .\access.log `
    -Pattern '/admin/settings/webhooks' |
    Select-Object LineNumber, Line
```

Relevant access-log events:

| Timestamp (UTC) | Source IP | Request | HTTP status |
|---|---|---|---:|
| 11 Mar 05:06:44 | `203.0.113.142` | GET `/admin/settings/webhooks` | 200 |
| 11 Mar 05:07:21 | `203.0.113.142` | POST `/admin/settings/webhooks` | 302 |
| 11 Mar 05:08:03 | `203.0.113.142` | POST `/admin/settings/webhooks/test` | 200 |
| 12 Mar 14:08:20 | `192.0.2.213` | GET `/admin/settings/webhooks` | 200 |

The DNS activity establishes name resolution, not successful HTTP callback delivery or data exfiltration. Outbound HTTP logs, webhook configuration details, payloads, and destination-side logs were unavailable.

### 8.2 Aegis Telemetry DNS Activity

The following command extracts TXT queries for the telemetry domain:

```powershell
$telemetryDns = $dns | Where-Object {
    $_ -match '\.t\.aegis-telemetry\.example'
}

"Total telemetry DNS queries: $($telemetryDns.Count)"

$telemetryDns | Select-Object -First 10
$telemetryDns | Select-Object -Last 10
```

Observed result: 575 TXT queries.

The source distribution was:

```powershell
$telemetryDns | Group-Object {
    if ($_ -match '10\.20\.5\.\d+') {
        $Matches[0]
    }
    else {
        'Unknown'
    }
} | Select-Object Name, Count
```

Observed results:

| Source host | Queries |
|---|---:|
| `10.20.5.18` | 288 |
| `10.20.5.17` | 287 |
| **Total** | **575** |

To group the records by their original UTC date without converting timestamps to local time:

```powershell
$telemetryDns |
    Group-Object { $_.Substring(0,10) } |
    Sort-Object Name |
    Select-Object Name, Count
```

Observed results:

| UTC date | Queries |
|---|---:|
| 2026-03-10 | 191 |
| 2026-03-11 | 192 |
| 2026-03-12 | 192 |
| **Total** | **575** |

The records show recurring TXT queries from both internal hosts across the observed period. This pattern may represent an internal telemetry or heartbeat mechanism, but its purpose cannot be confirmed from DNS logs alone.

The IT team should confirm the ownership and expected behaviour of these hosts and the telemetry domain. DNS resolution by itself does not establish data exfiltration.

## 9. Internal Vulnerability Scanner – Benign Activity

The environment notes identify `10.20.9.50` as the internal vulnerability scanner, scheduled for 10 March 14:00–14:30 UTC.

### 9.1 Scanner Access Requests

```powershell
$scannerAccess = $acc | Where-Object {
    $_ -match '^10\.20\.9\.50 - '
}

"Scanner requests: $($scannerAccess.Count)"

$scannerAccess | Select-Object -First 1
$scannerAccess | Select-Object -Last 1
```

Observed results:

- 248 HTTP requests.
- First request: 10 March 2026, 14:00:03 UTC.
- Last request: 10 March 2026, 14:10:44 UTC.
- User-Agent: `NordiaVulnScan/3.2 (internal)`.

### 9.2 HTTP Status Distribution

```powershell
$scannerAccess | ForEach-Object {
    if ($_ -match '"\s+(\d{3})\s+') {
        $Matches[1]
    }
} | Group-Object |
    Sort-Object Name |
    Select-Object Name, Count |
    Format-Table -AutoSize
```

Observed results:

| Status | Count |
|---|---:|
| 200 | 78 |
| 302 | 6 |
| 400 | 13 |
| 401 | 25 |
| 403 | 6 |
| 404 | 120 |
| 5xx | 0 |

### 9.3 Scanner Authentication Failures

```powershell
$scannerFailures = $auth | Where-Object {
    $_.event -eq 'login_failure' -and
    $_.src_ip -eq '10.20.9.50'
}

"Scanner authentication failures: $($scannerFailures.Count)"

$scannerFailures |
    Group-Object portal |
    Select-Object Name, Count |
    Format-Table -AutoSize

"Successful scanner logins: $(
    @($auth | Where-Object {
        $_.event -eq 'login_success' -and
        $_.src_ip -eq '10.20.9.50'
    }).Count
)"
```

Observed results:

- 12 failed authentication attempts.
- 6 customer portal failures.
- 6 admin portal failures.
- All failures reported `reason=unknown_user`.
- No successful login from the scanner IP.

The scanner activity is consistent with the scheduled internal scan and is not evidence of the primary intrusion.

## 10. Detection Rules Tested

### Rule 1 – Failed Logins Followed by Success

**Detection logic:** Alert when an IP generates at least 10 failed logins within 10 minutes and is followed by a successful login from the same IP within 20 minutes after the last failure.

**PowerShell command:**

```powershell
$culture = [System.Globalization.CultureInfo]::InvariantCulture

$failedLogins = $auth | Where-Object {
    $_.event -eq 'login_failure'
} | ForEach-Object {
    [PSCustomObject]@{
        Timestamp = [datetime]::Parse(
            $_.timestamp,
            $culture,
            [System.Globalization.DateTimeStyles]::RoundtripKind
        )
        IP = $_.src_ip
        Username = $_.username
        Portal = $_.portal
    }
} | Sort-Object Timestamp

$successfulLogins = $auth | Where-Object {
    $_.event -eq 'login_success'
} | ForEach-Object {
    [PSCustomObject]@{
        Timestamp = [datetime]::Parse(
            $_.timestamp,
            $culture,
            [System.Globalization.DateTimeStyles]::RoundtripKind
        )
        IP = $_.src_ip
        Username = $_.username
        Portal = $_.portal
    }
} | Sort-Object Timestamp

$alerts = foreach ($ipGroup in ($failedLogins | Group-Object IP)) {
    $failures = @($ipGroup.Group | Sort-Object Timestamp)
    $foundAlert = $false

    for ($i = 0; $i -lt $failures.Count -and -not $foundAlert; $i++) {
        $windowStart = $failures[$i].Timestamp
        $windowEnd = $windowStart.AddMinutes(10)

        $windowFailures = @(
            $failures | Where-Object {
                $_.Timestamp -ge $windowStart -and
                $_.Timestamp -le $windowEnd
            }
        )

        if ($windowFailures.Count -ge 10) {
            $lastFailure = (
                $windowFailures |
                Sort-Object Timestamp |
                Select-Object -Last 1
            ).Timestamp

            $success = $successfulLogins |
                Where-Object {
                    $_.IP -eq $ipGroup.Name -and
                    $_.Timestamp -gt $lastFailure -and
                    $_.Timestamp -le $lastFailure.AddMinutes(20)
                } |
                Sort-Object Timestamp |
                Select-Object -First 1

            if ($success) {
                [PSCustomObject]@{
                    SourceIP = $ipGroup.Name
                    FailedAttempts = $windowFailures.Count
                    FirstFailure = $windowStart
                    LastFailure = $lastFailure
                    SuccessTime = $success.Timestamp
                    SuccessfulUser = $success.Username
                    Portal = $success.Portal
                }

                $foundAlert = $true
            }
        }
    }
}

$alerts | Format-Table -AutoSize
```

**Observed suspicious sequences:**

- `198.51.100.77`: 70 failures between 01:58:03 and 02:07:54 UTC, followed by a customer login success at 02:24:48 UTC.
- `203.0.113.142`: 72 failures between 02:57:35 and 03:07:31 UTC, followed by a customer login success at 03:27:23 UTC.

This rule identifies suspicious authentication sequences. It does not prove that the successful login resulted from the preceding failed attempts.

### Rule 2 – Bulk Customer Export

**Detection logic:** Alert when one source IP makes at least three customer export requests with `size=500` within a 60-minute window.

**PowerShell command:**

```powershell
$culture = [System.Globalization.CultureInfo]::InvariantCulture

$largeExports = foreach ($line in $exports) {
    if ($line -match '^(\S+) - (\S+) \[(.*?)\] "GET /admin/customers/export\?([^ ]+)') {
        $ip = $Matches[1]
        $username = $Matches[2]
        $dateText = $Matches[3]
        $query = $Matches[4]

        if ($query -match '(?:^|&)size=(\d+)') {
            $pageSize = [int]$Matches[1]

            if ($pageSize -eq 500) {
                $dateText = $dateText -replace '([+-]\d{2})(\d{2})$', '$1:$2'

                $timestamp = [datetime]::ParseExact(
                    $dateText,
                    'dd/MMM/yyyy:HH:mm:ss zzz',
                    $culture
                ).ToUniversalTime()

                [PSCustomObject]@{
                    IP = $ip
                    Username = $username
                    Timestamp = $timestamp
                }
            }
        }
    }
}

$exportAlerts = foreach ($ipGroup in ($largeExports | Group-Object IP)) {
    $requests = @($ipGroup.Group | Sort-Object Timestamp)

    for ($i = 0; $i -lt $requests.Count; $i++) {
        $start = $requests[$i].Timestamp
        $end = $start.AddMinutes(60)

        $window = @(
            $requests | Where-Object {
                $_.Timestamp -ge $start -and
                $_.Timestamp -le $end
            }
        )

        if ($window.Count -ge 3) {
            [PSCustomObject]@{
                SourceIP = $ipGroup.Name
                Username = $window[0].Username
                Requests = $window.Count
                FirstSeen = $start
                LastSeen = (
                    $window |
                    Sort-Object Timestamp |
                    Select-Object -Last 1
                ).Timestamp
            }

            break
        }
    }
}

$exportAlerts | Format-Table -AutoSize
```

**Observed alert:**

- Source IP: `203.0.113.142`
- Account: `l.fontaine`
- Three large exports between 09:19:15 and 10:05:01 UTC.
- Supporting access-log lines: 4440, 4510, and 4572.
- The normal office source `192.0.2.50` did not meet this threshold.

### Rule 3 – Unexpected Account Creation

**Detection logic:** Alert whenever an account creation event occurs, especially when the event creates an administrative account.

**PowerShell command:**

```powershell
$accountCreationAlerts = $auth | Where-Object {
    $_.event -eq 'account_created'
} | ForEach-Object {
    [PSCustomObject]@{
        Timestamp = $_.timestamp
        Account = $_.username
        Actor = $_.actor
        SourceIP = $_.src_ip
        Portal = $_.portal
        Details = $_.detail
    }
}

$accountCreationAlerts | Format-List
```

**Observed alert:**

- One account creation event.
- Account: `svc-backup01`
- Actor: `l.fontaine`
- Source IP: `203.0.113.142`
- Assigned role: `admin`
- Creation method: `admin_ui`

These rules are detection heuristics. Their alerts require investigation and correlation with other evidence; they are not proof of account compromise or data exfiltration.

## 11. Evidence Limitations

The following evidence was not available:

- Database audit logs.
- Firewall, proxy, and outbound network logs.
- Email delivery and security notification logs.
- Webhook destination logs and actual callback payloads.
- Full forensic images of web and database servers.
- Endpoint telemetry sufficient to attribute activity to a specific person.
- Application audit records identifying the exact profile fields changed by the C2 profile request.
- Independent confirmation of the purpose and ownership of the Aegis telemetry domain and internal hosts.

Consequently, the investigation cannot establish whether exported data was received by an external party, identify every customer record accessed, or prove the identity of the person using the suspicious accounts.

HTTP 200 responses indicate successful HTTP responses, not proof that data was subsequently exfiltrated.

HTTP 403 responses indicate denied requests, not successful downloads.

DNS resolution establishes that a domain was resolved, not that a webhook callback was successfully delivered.

The access log records a POST request to `/account/profile` for `sonia.moreau@atelier-vega.example` on 12 March 2026 at 10:07:13 UTC from `203.0.113.37` (line 6865). The log does not expose the submitted fields or establish what profile data changed. The source IP differs from the IP used during the suspicious login on 11 March. Application audit records would be required to determine the exact change and assess its legitimacy.

The 575 Aegis telemetry TXT queries originated from two internal hosts, `10.20.5.17` and `10.20.5.18`. Their recurring pattern may be consistent with telemetry or heartbeat activity, but the available DNS records do not establish the domain's purpose or prove that the activity was benign or malicious.

## 12. Reproduction and Interpretation Notes

- Run commands from the directory containing the original evidence files.
- Keep the supplied evidence files unchanged.
- All timestamps in the source logs are UTC.
- Use `Select-String` to retrieve physical source line numbers for report references.
- Treat IP ownership, account ownership, and attacker identity as unconfirmed unless independently supported.
- DNS resolution is not proof of callback delivery.
- A requested export page size is not proof of unique records transferred.
- Distinguish customer invoice downloads from administrative invoice exports.
- Distinguish successful HTTP 200 downloads from denied HTTP 403 requests.
- The internal scanner activity must be distinguished from the suspicious external authentication and export activity.
- Detection rules are investigative heuristics and should be tuned against normal business activity before production deployment.
- Correlate account-role snapshots with role-change audit records before drawing conclusions about privilege changes.
- Correlate profile-update requests with application audit records before claiming that specific profile data changed.

