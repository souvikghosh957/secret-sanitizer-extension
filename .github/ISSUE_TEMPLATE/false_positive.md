---
name: False Positive Report
about: Report a legitimate string being incorrectly masked
title: "[False Positive] "
labels: false-positive
---

## What Was Masked

Describe the text that was incorrectly flagged (use dummy/example values, NOT real secrets).

## Which Pattern Triggered It

Hover over the toast's "secrets masked" text to see the rule (e.g. "AWS access key", "Random-looking tokens"), or copy the placeholder name (e.g. `QUOTED_SECRET`).

## Where It Happened

Which AI platform (ChatGPT, Claude, etc.)?

## Why It's Not a Secret

Explain why this string is legitimate and shouldn't be masked.

> **Warning:** Do NOT include real secrets, API keys, or credentials in this issue. Use dummy/example values only.
