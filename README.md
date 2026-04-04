# cvepipe

## Requirements
- docker (for local searXNG server)
- uv (https://docs.astral.sh/uv/getting-started/installation/)
- debian/ludus installed on a dedicated machine
- NIST NVD api key
- openAI-compatible endpoint credentials
- download relevant windows ISOs (https://archive.org/download/english_windows_collection)

To install dependencies:

```bash
bun i
uv init --python 3.12
uv add ansible pywinrm
uv sync
cd ./searXNGDocker/ && docker compose up -d
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

LUDUS_API_URL=
LUDUS_API_KEY=

```

## Phase 1: Metasploit Module Classification
- extracts metadata from Metasploit Framework exploit modules and classifies them based on VM reproducibility for automated windows lab provisioning with ludus.

```bash
bun run modules/metasploitMetadataExtract.js
```

```bash
# ran heuristic/llm hybrid approach on March 29 2026
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

```bash
# llm only approach on March 29 2026
============================================================
METASPLOIT WINDOWS EXPLOIT MODULE ANALYSIS
============================================================
[RESULT] Total Windows exploit modules: 1224
[RESULT] VM-replicable (initial foothold): 709 (57.9%)
[RESULT] NOT replicable: 515 (42.1%)

Breakdown of non-replicable by category:
  client_side: 503
  unknown: 10
  local_privesc: 2

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
  initial_foothold: 564
  client_side: 503
  privilege_escalation: 117
  lateral_movement: 30
  unsupported: 10

Breakdown by provisioning complexity:
  third_party_software: 1007
  standard: 196
  service_configuration: 21
[OUTPUT] Written: output/filtered_modules.json
[OUTPUT] Written: output/analysis_summary.json
[CACHE] Saved 1224 entries to modules/filteredModules.json
```

## Phase 2: multi stage Scenario Pre-Screening 
```bash
bun run scenario/prescreen.js
```
##### stage 1:
─────────────────────────────────────────────────────────────────────────┐
│                         STAGE 1: UNDERSTAND VULNERABILITY               │
├─────────────────────────────────────────────────────────────────────────┤
│ 1. PLANNER (stage1Planner)                                              │
│    Input: Raw exploit entry                                             │
│    Output: 2 Tasks                                                      │
│    LLM Calls: 0                                                         │
│                                                                         │
│ 2. EXECUTOR (sequential, priority-sorted)                               │
│    ├─ Task A: web_search                                                │
│    │   Query: "\"{name}\" vulnerability {year}"                         │
│    │   Source: SearXNG HTTP fetch                                       │
│    │   LLM Calls: 0                                                     │
│    │   Output: 10 search results + metadata                             │
│    │                                                                    │
│    └─ Task B: reasoning                                                 │
│        Query: "Based on name alone, what vuln type/component/trigger?"  │
│        Source: LLM                                                      │
│        LLM Calls: ✅ CALL #1                                            │
│        Output: Raw text hypotheses                                      │
│                                                                         │
│ 3. SYNTHESIZER (stage1Synthesizer)                                      │
│    Input: entry + search results + reasoning text + 7 fetched pages     │
│    Prompt: "VULNERABILITY RESEARCH SYNTHESIS → Output JSON..."          │
│    Source: LLM                                                          │
│    LLM Calls: ✅ CALL #2                                                │
│    Output: { vulnerability_type, affected_component, trigger_condition, │
│              preconditions, impact, technical_indicators,               │
│              confidence, unknowns }                                     │
│                                                                         │
│ 4. CONFIDENCE GATE                                                      │
│    If conf ≥ 0.7 → ✅ EXIT → Save checkpoint → Pass to Stage 2          │
│    If conf < 0.7 → 🔁 LOOP → Planner targets unknowns → Re-synthesize   │
└─────────────────────────────────────────────────────────────────────────┘

##### stage 2:
─────────────────────────────────────────────────────────────────────────┐
│                         STAGE 2: UNDERSTAND SOFTWARE                    │
├─────────────────────────────────────────────────────────────────────────┤
│ 0. RESUME CHECK (if rerun)                                              │
│    loadCheckpoint() → restores Stage 1 output → skips Stage 1 entirely  │
│                                                                         │
│ 1. PLANNER (stage2Planner)                                              │
│    Input: Raw entry + Stage 1 mental model                              │
│    Output: 3-4 Tasks (4 if Microsoft)                                   │
│    LLM Calls: 0                                                         │
│                                                                         │
│ 2. EXECUTOR (sequential, priority-sorted)                               │
│    ├─ Task A: web_search (software ID)                                  │
│    │   Query: "\"{product}\" {vendor} software history version {ver}"   │
│    │   Source: SearXNG                                                  │
│    │   LLM Calls: 0                                                     │
│    │                                                                    │
│    ├─ Task B: web_search (acquisition recon)                            │
│    │   Query: "\"{product}\" download archive legacy version"           │
│    │   Source: SearXNG                                                  │
│    │   LLM Calls: 0                                                     │
│    │                                                                    │
│    ├─ Task C: reasoning (classification)                                │
│    │   Query: "Vuln context: {Stage1 JSON}. What type of software?"     │
│    │   Source: LLM                                                      │
│    │   LLM Calls: ✅ CALL #1                                            │
│    │                                                                    │
│    └─ Task D: reasoning (Windows expert) [MS ONLY]                      │
│        Query: "Microsoft \"{product}\". Enable via Features? Versions?" │
│        Source: LLM                                                      │
│        LLM Calls: ✅ CALL #2 [Conditional]                              │
│                                                                         │
│ 3. SYNTHESIZER (stage2Synthesizer)                                      │
│    Input: entry + Stage 1 model + search results + reasoning texts      │
│    Prompt: "SOFTWARE PROFILE: {product} → Output JSON..."               │
│    Source: LLM                                                          │
│    LLM Calls: ✅ CALL #3                                                │
│    Output: { canonical_name, vendor, version_timeline, software_type,   │
│              installation_method, dependencies, licensing,              │
│              acquisition_difficulty, lab_notes, confidence, unknowns }  │
│                                                                         │
│ 4. CONFIDENCE GATE                                                      │
│    If conf ≥ 0.7 → ✅ EXIT → Save checkpoint → Pass to Stage 3          │
│    If conf < 0.7 → 🔁 LOOP → Targets gaps → Re-synthesize               │
└─────────────────────────────────────────────────────────────────────────┘

##### stage 3:
┌─────────────────────────────────────────────────────────────────────────┐
│                    STAGE 3: CLASSIFY & STRATEGIZE                       │
├─────────────────────────────────────────────────────────────────────────┤
│ 0. RESUME CHECK (if rerun)                                              │
│    loadCheckpoint() → restores Stage 1+2 outputs → skips prior stages   │
│                                                                         │
│ 1. PLANNER (stage3Planner)                                              │
│    Input: raw entry + Stage 1 model + Stage 2 profile                   │
│    Branch: Microsoft vs Third-Party + confidence check                  │
│    Output: 2-4 Tasks                                                    │
│    LLM Calls: 0                                                         │
│                                                                         │
│ 2. EXECUTOR (sequential, priority-sorted)                               │
│    ├─ Microsoft Path:                                                   │
│    │  ├─ Task A: reasoning (PowerShell expert)                          │
│    │  │   Source: LLM → ✅ CALL #1                                      │
│    │  └─ Task B: web_search (verify commands)                           │
│    │      Source: SearXNG → 0 LLM calls                                 │
│    │                                                                    │
│    ├─ Third-Party Path:                                                 │
│    │  ├─ Task A: web_search (exact version)                             │
│    │  ├─ Task B: web_search (vendor archive) [if vendor known]          │
│    │  ├─ Task C: archive_lookup (installer)                             │
│    │  └─ Task D: open_ended (if confidence < 0.5)                       │
│    │      Source: LLM generates sub-queries → ✅ CALL #1 (conditional)  │
│    │                                                                    │
│ 3. SYNTHESIZER (stage3Synthesizer)                                      │
│    Input: entry + Stage 1+2 models + search results + reasoning + links │
│    Prompt: "ACQUISITION STRATEGY: {product} → Output JSON..."           │
│    Source: LLM                                                          │
│    LLM Calls: ✅ CALL #2 (or #3 if open_ended triggered)                │
│    Output: { strategy_type, specific_steps, prerequisites,              │
│              risk_assessment, fallback_options, estimated_effort,       │
│              confidence, unknowns }                                     │
│                                                                         │
│ 4. CONFIDENCE GATE                                                      │
│    If conf ≥ 0.7 → ✅ EXIT → Save checkpoint → Pass to Stage 4 (or exit)│
│    If conf < 0.7 → 🔁 LOOP → Targets gaps → Re-synthesize               │
└─────────────────────────────────────────────────────────────────────────┘

##### stage 4:
┌─────────────────────────────────────────────────────────────────────────┐
│                    STAGE 4: FIND DOWNLOADS (FINAL VERIFICATION)         │
├─────────────────────────────────────────────────────────────────────────┤
│ 0. RESUME CHECK (if rerun)                                              │
│    loadCheckpoint() → restores Stage 1/2/3 outputs → skips prior stages │
│                                                                         │
│ 1. PLANNER (stage4Planner)                                              │
│    Input: raw entry + Stage 1 model + Stage 2 profile + Stage 3 strategy│
│    Branch: strategy_type determines task generation                     │
│    Output: 2-5 Tasks                                                    │
│    LLM Calls: 0                                                         │
│                                                                         │
│ 2. EXECUTOR (sequential, priority-sorted)                               │
│    ├─ IF strategy_type == "enable_windows_feature":                     │
│    │  ├─ Task A: web_search (verify PowerShell/DISM commands)           │
│    │  │   Query: "verify 'Enable-WindowsOptionalFeature...' docs"       │
│    │  │   Source: SearXNG → 0 LLM calls                                 │
│    │  │                                                                 │
│    │  └─ Task B: reasoning (validate commands)                          │
│    │      Query: "Validate Windows enablement for IIS: [steps]..."      │
│    │      Source: LLM → ✅ CALL #1                                      │
│    │                                                                 │
│    ├─ ELSE (download-focused strategies):                               │
│    │  ├─ Task A: web_search (direct file search)                        │
│    │  │   Query: '"{product}" "{version}" filetype:exe OR filetype:msi' │
│    │  │   Source: SearXNG → 0 LLM calls                                 │
│    │  │                                                                 │
│    │  ├─ Task B: web_search (archive.org search)                        │
│    │  │   Query: 'site:archive.org "{product}" "{version}" download'    │
│    │  │   Source: SearXNG → 0 LLM calls                                 │
│    │  │                                                                 │
│    │  ├─ Task C: web_search (vendor legacy, if known)                   │
│    │  │   Query: 'site:vendor.com "legacy" "{product}"'                 │
│    │  │   Source: SearXNG → 0 LLM calls                                 │
│    │  │                                                                 │
│    │  └─ Task D: reasoning (URL verification, for each candidate URL)   │
│    │      Query: "Verify download URL: {url}. Check domain, file type..."│
│    │      Source: LLM → ✅ CALL #1 (per URL, up to 3)                   │
│    │                                                                 │
│    └─ IF low confidence from Stage 3:                                   │
│       └─ Task E: open_ended (desperate fallback search)                 │
│           Source: LLM generates sub-queries → ✅ CALL #2 (conditional)  │
│                                                                         │
│ 3. SYNTHESIZER (stage4Synthesizer)                                      │
│    Input: entry + Stage 1-3 models + search results + reasoning +       │
│           validated candidate URLs (with HEAD request metadata)         │
│    Prompt: "FINAL DOWNLOAD VERIFICATION: {product} → Output JSON..."    │
│    Source: LLM                                                          │
│    LLM Calls: ✅ CALL #N (final synthesis call)                         │
│    Output: {                                                            │
│      recommendation: "download_url|enable_feature_command|build_source|not_feasible",
│      value: "string (URL or command)",                                  │
│      verification_steps: ["string"],                                    │
│      risk_warnings: ["string"],                                         │
│      confidence: 0.0-1.0,                                               │
│      next_steps: ["string"]                                             │
│    }                                                                    │
│                                                                         │
│ 4. CONFIDENCE GATE                                                      │
│    If conf ≥ 0.7 → ✅ EXIT → Save checkpoint → Return final result      │
│    If conf < 0.7 → 🔁 LOOP → Targets gaps → Re-synthesize               │
│    Max loops: 5 → Force exit with best-effort output                    │
└─────────────────────────────────────────────────────────────────────────┘

## Phase 3: Agentic exploit validation loop



#### RE: Windows 2012 R2 server 
Install .NET Framework 4.8 (offline installer)
Then install WMF 5.1 

```cmd
sc config wuauserv start= demand
sc config bits start= demand
sc config cryptsvc start= demand

net start wuauserv
net start bits
net start cryptsvc
```

