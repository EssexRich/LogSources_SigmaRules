# LogSources & Sigma Rules Library

Comprehensive log source field mappings and Sigma detection rules for threat detection across Windows, Linux, macOS, and cloud platforms.

## Structure

- **`logsources.json`** - Master log source library with field mappings for all supported products and services
- **`sigma-rules/`** - Generated Sigma detection rules (one per MITRE ATT&CK technique)
- **`scripts/`** - Generation and utility scripts

## Log Sources Covered

### Operating Systems
- Windows (Event Log, Sysmon, ETW)
- Linux (auditd, osquery, journalctl)
- macOS (Unified Logging, ESF, osquery)

### Cloud Platforms
- Microsoft: M365, Defender, Defender for Cloud, Entra ID
- Google: Workspace, Cloud Logging

## Sigma Rules

Rules are generated automatically from logsources and MITRE ATT&CK technique data. Each rule includes:
- MITRE technique reference
- Logsource definition
- Field mappings for supported products
- Detection logic
- SEO-optimized description

## Generation

Rules and logsources are generated via admin interface in IncidentBuddy. See `scripts/generate-logsources.js` for generation logic.

## Usage

Import `logsources.json` in your detection rule generation pipeline to:
1. Map abstract Sigma fields to product-specific field names
2. Generate rules for specific log sources
3. Convert rules to SIEM-specific formats

## License

MIT
