# Phishing Email Triage

## Purpose

Phishing cases can branch fast. While some are just noisy spam, others turn into credential theft, malware execution, or account compromise. 
The goal of this workflow is to help me stay organized, answer the most important questions early, and document the case clearly enough that another analyst could follow the logic without starting over.

I’m not treating this as a rigid enterprise playbook. It’s a practical triage workflow I can refine over time as I get more hands-on experience.

> [!NOTE]
> The goal is to write down my thought process in a way that is repeatable for anyone to understand. This helps me to stay consistent, avoid missing obvious evidence, and to leave behind useful notes.

## At a Glance

When I triage a phishing email, I’m usually trying to answer four things first:

1. Is the sender and delivery path trustworthy?
2. Are the links or attachments suspicious?
3. Did the user interact with the message?
4. Does this stay an email case, or does it become an identity or endpoint case?

---

## 1. Understand the Email at a High Level

Before I get pulled into headers or tooling, I want to understand the basic story of the email. That helps me frame the rest of the case instead of jumping straight into artifacts without context.

### What I’m trying to answer

- What is the lure?
- What is the user being pushed to do?
- Does this look more like credential theft, malware delivery, or general social engineering?

Some early red flags include urgent language, spoofed branding, mismatched sender details, login-themed wording, QR codes, strange tone, or unexpected attachments.

> [!NOTE]
> Can I describe this lure in one sentence? If not, I probably need to slow down.
---

## 2. Review the Sender and Headers

This is where I want to answer a simple question: did this message actually come from where it claims to have come from?

The visible sender can be misleading, so I compare the display name and sender address against the underlying mail path. A phishing email can look normal at a glance but still fall apart once the routing and authentication details are checked.

### Header fields I care about most

- `From`
- `Reply-To`
- `Return-Path`
- `Received`
- `Message-ID`
- `Authentication-Results`
- `X-Originating-IP` if present

I read the `Received` chain from the bottom up and focus on the earliest trustworthy public-facing hop. I also check whether `SPF`, `DKIM`, and `DMARC` support the sender’s identity, but I don’t treat those results as the final answer.

> [!NOTE]
> Passing SPF, DKIM, or DMARC doesn’t automatically make an email safe. It only tells me part of the delivery story.

### Quick check

- Does the display name impersonate someone trusted?
- Does `Reply-To` point somewhere unexpected?
- Does the visible sender conflict with the return path?
- Does the sending path make sense for the claimed sender?

---

## 3. Extract and Defang URLs

If the email contains links, I extract them carefully and defang them before documenting or sharing them. That keeps the process safer and makes it easier to include findings in notes or tickets without creating unnecessary risk.

Examples:

- `http://example.com` becomes `hxxp://example[.]com`
- `https://login-example.com/reset` becomes `hxxps://login-example[.]com/reset`

### What I’m checking here

- Does the visible link text match the real destination?
- Is the domain pretending to be a legitimate brand?
- Are redirects, shorteners, or tracking links involved?
- Does the path suggest credential harvesting or file download?

Common clues include typo-squatted domains, random-looking subdomains, shortened links, unrelated login pages, or QR codes that hide the destination until scanned.

---

## 4. Review Attachments Safely

If there’s an attachment, I want to understand what it is before opening anything. File name and extension alone aren't enough. I want to know what the file claims to be, what it actually is, and whether it looks like part of a delivery chain.

### Initial checks

- file name
- extension
- actual file type
- hash values
- password protection
- whether the extension matches the true content

Some file types deserve extra attention because they show up often in phishing activity or can hide risky behavior behind a familiar format. These include Office documents, PDFs, archives, HTML files, OneNote files, and shortcut-based delivery chains.

> [!WARNING]
> If a file is heavily obfuscated or clearly suspicious, convenience shouldn’t override judgment. Throwing samples into random public tools can leak case details and create bad habits.

### Quick check

- Is the file type consistent with the extension?
- Is this trying to trigger another stage of execution?
- Does the attachment fit the lure, or does it feel forced?

---

## 5. Decide What Type of Phishing This Is

Once I’ve reviewed the message, links, and attachments, I try to place the case into a working category.
Common buckets include credential harvesting, malware delivery, session hijacking, and business email compromise or callback fraud.

This matters because the response path changes depending on the goal. Credential theft pushes me toward account review and sign-in activity. Malware delivery pushes me toward endpoint execution, persistence, and outbound connections.

---

## 6. Check for User Impact

This is one of the most important parts of the workflow.

### What I’m trying to answer

- Did the user click the link?
- Did they open the attachment?
- Did they submit credentials?
- Did any related activity occur on the endpoint?
- Did the same email reach other users?

If I have endpoint telemetry, this is where I pivot from email review into host investigation.

### Common Pivots

If the case starts moving beyond the email itself, I want to pivot in a way that matches the evidence instead of chasing everything at once.

A few common pivots that matter in phishing cases:

- **Identity activity**  
  If credentials may have been submitted, I want to review sign-in activity, MFA prompts, session changes, failed logons, impossible travel, or anything else that suggests account misuse.

- **Mailbox activity**  
  If account compromise is suspected, I want to check for mailbox rules, forwarding behavior, deleted messages, or other changes that may show follow-on abuse.

- **Endpoint activity**  
  If an attachment was opened or a link led to a download, I want to look for process execution, child processes, browser activity, archive extraction, persistence, and outbound connections.

- **Delivery scope**  
  If the email was malicious, I want to know who else received it. Did the same message reached multiple users?

- **Infrastructure reuse**  
  If a URL, sender, domain, or hash is confirmed suspicious, I want to check whether the same artifacts show up elsewhere in the environment or in related cases.

The point here is to follow the evidence far enough to understand whether the problem stayed in the inbox or moved somewhere else.

---

## 7. Determine Containment or Escalation Needs

The next step depends on what actually happened. If the message appears to be delivery only, the focus may stay on blocking, scoping, and removing similar emails. 
If the user clicked or submitted credentials, the urgency changes. If malware execution is suspected then I’m dealing with endpoint risk.

### Possible actions

- block the sender, domain, or URL
- remove similar emails from other mailboxes if possible
- review sign-in activity
- check for mailbox rules, forwarding, or MFA abuse
- preserve hashes and execution details
- isolate or contain the host according to procedure
- escalate for deeper endpoint investigation

> The point here isn’t to run through a giant generic checklist but to connect the evidence to the next decision.

---

## 8. Document the Case Clearly

Good notes are part of the investigation and if I don’t document what I found in a way someone else can follow, I’m making the next analyst redo work that should already be captured.

### Case notes should include

- case summary
- source of the report or alert
- sender
- subject line
- delivery time
- recipients
- authentication results
- extracted URLs
- attachment names and hashes
- suspected phishing type
- user interaction status
- verdict
- containment actions taken
- recommended follow-up

> [!NOTE]
> Documentation should explain the evidence behind the "Suspicious" label.

---

## Before Closing the Case

Before I close or hand off the case, I want to make sure I didn’t rush past something important.

- Did I verify the sender path instead of trusting the display name?
- Did I extract and defang all URLs?
- Did I identify and hash any attachments?
- Did I check whether the user interacted with the email?
- Did I document my reasoning clearly enough for someone else to follow?
- Did I escalate if the case showed signs of credential theft or endpoint execution?
