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
