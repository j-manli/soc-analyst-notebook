# Phishing Email Triage

## Purpose

Phishing cases can branch in a lot of directions fast. Some are just noisy spam. Others turn into credential theft, malware execution, or account compromise. 
The goal of this workflow is to help me stay organized, answer the most important questions early, and document the case in a way that another analyst could follow without starting over.

I’m not treating this as a rigid enterprise playbook. It’s a practical workflow I can keep refining as I get more hands-on experience with phishing triage and investigation.

> [!NOTE]
> The goal is to write down my thought process in a way that is repeatable for anyone to understand. This helps me to stay consistent, avoid missing obvious evidence, and to leave behind useful notes.

## Inputs

A phishing case might begin with a user report, an email file, raw headers, a suspicious URL, an attachment, or an alert from an email security tool, endpoint tool, or SIEM. No matter how it starts, I’m trying to answer the same basic questions:

- Is the message malicious, suspicious, or benign?
- What infrastructure, links, or files are involved?
- Did the user interact with it?
- What needs to be documented, contained, or escalated?

## Expected Outputs

By the end of triage, I want to walk away with a usable case summary and as many of the following as possible:

- sender address and sending path
- SPF, DKIM, and DMARC results
- extracted and defanged URLs
- attachment names, hashes, and true file types
- basic delivery scope
- initial verdict
- next steps for containment or escalation

## 1. Understand the Email at a High Level

Before I get pulled into headers or tooling, I want to understand what kind of message I’m looking at. If the lure is clearly login-themed, I’m already thinking about credential theft. 
If it’s an attachment-based invoice lure, I’m thinking more about malware delivery or staged payloads.

At this stage, I’m trying to get the basic story straight. What is the email trying to make the user do? Is it pushing urgency, trust, fear, curiosity, or routine business activity? 
Is it pretending to be a vendor, a Microsoft 365 login, a shared document, a voicemail, or an internal message?

Some of the first red flags I look for are:

- urgent or threatening language
- spoofed branding
- mismatched sender display name
- strange tone or grammar
- unexpected attachment
- login-themed wording
- QR codes
- suspicious reply instructions

> [!TIP]
> Before digging into technical details, can I describe this lure in one sentence? If not, I probably need to slow down.

## 2. Review the Sender and Headers

This is where I want to answer a simple question: did this message actually come from where it claims to have come from?

The visible sender can be misleading, so I compare the display name and sender address against the underlying mail path. A phishing email can look normal at first glance but still reveal itself through mismatched routing details, reply paths, or authentication failures.

The header fields I care about most are:

- `From`
- `Reply-To`
- `Return-Path`
- `Received`
- `Message-ID`
- `Authentication-Results`
- `X-Originating-IP` if present

I read the `Received` chain from the bottom up and focus on the earliest trustworthy public-facing hop. I also check whether SPF, DKIM, and DMARC support the sender’s identity, but I don’t treat those results as the final answer. 
A message can still be malicious even if parts of the mail flow look legitimate.

Does the technical story match the visible story? If the display name says one thing and the reply path or sending infrastructure says another, that's a problem.

> [!NOTE]
> Passing SPF, DKIM, or DMARC doesn’t automatically make an email safe. It only tells me something about parts of the mail path and sender alignment.

## 3. Extract and Defang URLs

If the email contains links, I extract them carefully and defang them before documenting or sharing them. That helps keep the investigation safe and makes it easier to include findings in notes, writeups, or tickets without creating accidental risk.

Examples:

- `http://example.com` becomes `hxxp://example[.]com`
- `https://login-example.com/reset` becomes `hxxps://login-example[.]com/reset`

Once I have the URLs, I want to understand whether the destination fits the message. Does the visible link text match the real destination? 
Is the domain pretending to be a legitimate brand? Are there redirects, shorteners, or tracking links involved? Does the path suggest credential harvesting, file download, or some other kind of lure?

A few common phishing clues to look for:

- login pages on unrelated domains
- typo-squatted domains
- random-looking subdomains
- shortened URLs
- domains that don’t fit the sender or message theme
- QR codes that hide the destination until scanned

If the email looks like credential phishing, I note that early. That changes the direction of the case quickly, especially if there’s any sign the user may have interacted with it.

## 4. Review Attachments Safely

If there’s an attachment, I want to understand what it is and what it does. File name and extension alone aren't enough. 
I want to know what the file claims to be, what it actually is, and whether it shows signs of being part of a delivery chain.

My first checks are usually:

- file name
- extension
- actual file type
- hash values
- whether the file is password protected
- whether the extension matches the true content

Some file types deserve extra attention because they show up often in phishing activity or can hide behavior behind a familiar format. 
For example, Office documents with macros or embedded content, PDFs with JavaScript or launch behavior, archives containing scripts or executables, HTML attachments, OneNote files, and image or shortcut-based delivery chains.

For Office files, I’m looking for macros, suspicious strings, auto-execution behavior, and signs the document is meant to launch something else. 
For PDFs, I’m interested in embedded files, JavaScript, `/OpenAction`, or anything that suggests the document triggers content automatically. 
For archives, I want to inspect the contents safely, preserve hashes, and verify what’s actually inside before jumping ahead.

> [!WARNING]
> If a file is heavily obfuscated or suspicious, I don’t want convenience to override judgment. Throwing a sample into random public tools without thinking can leak case details and create bad habits.

## 5. Decide What Type of Phishing This Is

Once I’ve looked at the message, links, and attachments, I try to place the case into a working category. I don’t need perfect classification at this stage, but I do need a reasonable sense of what kind of problem I’m dealing with.

A few common buckets are:

- **Credential phishing** e.g. fake Microsoft 365 logins, password resets, MFA prompts, or shared document lures
- **Malware delivery** e.g. scripts, macro documents, archives, executables, or staged payloads
- **Reply-chain phishing / conversation hijacking** e.g. abuse of an existing thread or compromised mailbox
- **BEC or callback fraud** e.g. social engineering aimed at payment fraud, direct contact, or trust abuse

This is important because the response path changes depending on the goal. 
Credential theft pushes me toward account review and sign-in activity. 
Malware delivery pushes me toward endpoint activity, execution, persistence, and outbound connections.

## 6. Check for User Impact

This is one of the most important parts of the workflow.

At this point I want to know:

- Did the user click the link?
- Did they open the attachment?
- Did they submit credentials?
- Did any related activity occur on the endpoint?
- Did the same email reach other users?

If I have endpoint telemetry, this is where I pivot from email analysis into host investigation.
I’m looking for browser activity tied to the phishing domain, process execution related to the attachment, archive extraction followed by script or binary execution, or suspicious sign-in activity after possible credential submission.

> [!TIP]
> This is usually the section that changes the case from “email triage” to “incident response.” Once user interaction is confirmed, the workflow often needs to widen *fast*.

## 7. Determine Containment or Escalation Needs

The next step depends on what happened. If the message appears to be delivery only, the focus may stay on blocking, scoping, and removing similar messages. 
If the user clicked a link, I need to think about browser activity, redirects, and any follow-on behavior. 
If credentials may have been submitted, the urgency goes up because the problem may now involve account compromise. 
If malware execution is suspected, I’m now dealing with endpoint risk.

Possible response actions include:

- blocking the sender, domain, or URL
- removing similar emails from other mailboxes if possible
- documenting affected recipients
- reviewing sign-in activity
- checking for mailbox rules, MFA abuse, or account changes
- preserving hashes and execution details
- isolating or containing the host according to procedure
- escalating for deeper endpoint investigation

I don’t want this section to become a giant generic checklist. The point is to connect the evidence to the next decision. What happened, what risk does it create, and who needs to know?

## 8. Document the Case Clearly

Good notes are part of the investigation. If I don’t document what I found in a way someone else can follow, I’m making the next analyst redo work that should already be captured.

At minimum, I want my notes to include:

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

A good case note should explain both what I found and why we should care. It should also make my reasoning visible enough that someone else can understand how I got to the verdict.

> [!NOTE]
> Documentation should explain the evidence behind the "Suspicious" label.

## 9. Self-Check Before Closing

Before closing or handing off the case, I want to do one last pass and make sure I didn’t rush through something important.

- Did I verify the real sender path instead of trusting the display name?
- Did I extract and defang all URLs?
- Did I hash and identify any attachments?
- Did I check whether the user clicked, opened, or submitted anything?
- Did I document enough for someone else to follow my reasoning?
- Did I escalate if there was possible credential theft or endpoint execution?

This final check helps keep the workflow practical. It’s less about perfection and more about making sure I covered the important ground before moving on.

## Closing Note

The point of this workflow isn’t to make phishing cases look neat on paper but to help me work them in a consistent way, think clearly under pressure, and leave behind notes that are actually useful.
