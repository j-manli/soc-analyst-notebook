# KQL Cheat Sheet

> Quick reference for common KQL functions

---

## Time Analysis
Use these for working with dates, times, ranges, and time buckets.

- `datetime()` — specific date/time value
- `startofday()` — beginning of a day
- `endofday()` — end of a day
- `between` — filter within a range
- `ago()` — relative time from now
- `bin()` — group values into buckets

---

## Aggregation
Use these to count, group, summarize, and rank data.

- `summarize` — group rows and calculate values
- `count()` — count rows
- `dcount()` — count distinct values
- `min()` — smallest / earliest value
- `max()` — largest / latest value
- `make_set()` — create a list of unique values
- `top` — show highest N results
- `sort` — order results

---

## Data Transformation
Use these to shape data or create new columns.

- `project` — keep or rename columns
- `extend` — add a new column
- `iff()` — simple if/else logic
- `case()` — multiple condition logic

---

## Advanced Filtering
Use these for text matching and filtering lists of values.

- `startswith` — begins with
- `endswith` — ends with
- `in` — matches any value in a list
- `!in` — does not match values in a list
- `has_any` — contains any of several terms

---
## EXAMPLES

### FILTER
```kusto
| where result == "Failed Login"
| where src_ip startswith "10."
| where filename endswith ".exe"
| where result in ("Failed Login", "Locked Out")
| where sender_domain !in ("company.com", "partner.com")
| where process_commandline has_any ("powershell", "wmic")
```

### TIME
```kusto
| where timestamp >= ago(7d)
| where timestamp between (datetime(2024-05-01) .. datetime(2024-05-07))
| where timestamp >= startofday(now())
| summarize count() by bin(timestamp, 1h)
```

### SHAPE
```kusto
| project timestamp, username, src_ip
| project EventTime = timestamp, User = username
| extend hour = hourofday(timestamp)
| extend status = iff(result == "Successful Login", "OK", "FAILED")
| extend risk = case(score > 90, "HIGH", score > 50, "MEDIUM", "LOW")
```

### AGGREGATE
```kusto
| summarize total = count() by username
| summarize unique_users = dcount(username) by src_ip
| summarize first_seen = min(timestamp), last_seen = max(timestamp) by sender
| summarize recipients = make_set(recipient) by subject
| top 5 by total desc
| sort by total desc
```
