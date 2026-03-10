# SOC Analyst Notebook

This repository is a collection of investigation notes, detection experiments, and small observations from my time practicing threat hunting and defensive analysis.

Most of the entries here started as simple questions:

- What does this process actually do?
- Why did this rule miss the activity?
- What does the log look like before and after execution?

Writing them down here helps me remember what I learned and refine the way I approach detection.

Some write-ups focus on:
- threat hunting exercises using Microsoft Defender for Endpoint (MDE)
- detection engineering (Sigma, YARA)
- Windows execution behavior
- log analysis using tools like Chainsaw or Splunk

The goal is not to present finished research, but instead, document the process of learning, testing ideas, and improving detection logic over time.

This repository will change as I continue to learn and refine things.

---

## How this repo is organized

Each write-up usually follows a similar flow:

1. What I noticed
2. What I investigated
3. What I tested
4. What detection logic came out of it

Many entries include screenshots, rule snippets, or command output that helped confirm what was happening.
