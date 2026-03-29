# cvepipe

To install dependencies:

```bash
bun i
```

## update `.env`
```
NVD_API_KEY=
LUDUS_API_KEY=
CALDERA_URL=
CALDERA_KEY=ADMIN123 

ADVERSARY_ID=

TARGET_HOST=

# OpenAI-compatible endpoint
LLM_API_KEY=
LLM_BASE_URL=
LLM_MODEL=
```

## Phase 1: Metasploit Module Classification
- extracts metadata from Metasploit Framework exploit modules and classifies them based on VM reproducibility for automated windows lab provisioning with ludus.

```bash
bun run modules/metasploitMetadataExtract.js
```

```bash
# ran on March 29 2026
============================================================
METASPLOIT WINDOWS EXPLOIT MODULE ANALYSIS
============================================================
[RESULT] Total Windows exploit modules: 1224
[RESULT] VM-replicable (initial foothold): 438 (35.8%)
[RESULT] NOT replicable: 786 (64.2%)

Breakdown of non-replicable by category:
  client_side_fileformat: 254
  unknown: 176
  client_side: 166
  local_privesc: 126
  client_side_browser: 64

------------------------------------------------------------
PLATFORM BREAKDOWN
------------------------------------------------------------
[PLATFORM] Windows-focused modules: 1200
[PLATFORM] Linux-focused modules: 1
[PLATFORM] Mixed/Other: 23

============================================================
ANALYSIS COMPLETE
============================================================


Breakdown by access type:
  initial_foothold: 438
  unknown: 429
  unsupported: 169
  client_side: 166
  privilege_escalation: 15
  lateral_movement: 7
[OUTPUT] Written: output/filtered_modules.json
[OUTPUT] Written: output/analysis_summary.json
```