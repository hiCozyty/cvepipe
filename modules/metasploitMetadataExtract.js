#!/usr/bin/env bun

/**
 * Metasploit Module Metadata Extractor
 */

import { $ } from 'bun';
import path from 'node:path';
import { OpenAI } from 'openai';

// ============================================================================
// Configuration
// ============================================================================

const METASPLOIT_DIR = './metasploit-framework';
const OUTPUT_DIR = './output';
const BATCH_SIZE = 5; // batch caching
const CLEAR_CACHE = true;
const LLM_ONLY_MODE = true; // (set true to bypass heuristics, send ALL to LLM)
const CACHE_DIR = './modules'; // New directory for cache
const CACHE_FILE_PATH = path.join(CACHE_DIR, 'filteredModules.json'); // New cache file
const WINDOWS_EXPLOITS_PATH = 'modules/exploits/windows';
const MAX_CONCURRENCY = 1;
const LLM_API_KEY = process.env.LLM_API_KEY;
const LLM_BASE_URL = process.env.LLM_BASE_URL;
const LLM_MODEL = process.env.LLM_MODEL;

const RATE_LIMIT_MS = 2000;
let lastRequestTime = 0;

async function rateLimitedDelay() {
    const now = Date.now();
    const elapsed = now - lastRequestTime;
    if (elapsed < RATE_LIMIT_MS) {
        await new Promise(resolve => setTimeout(resolve, RATE_LIMIT_MS - elapsed));
    }
    lastRequestTime = Date.now();
}

// ============================================================================
// Helper Functions
// ============================================================================

function parseLLMJson(response) {
    try {
        const cleaned = response.replace(/```json?\n?/g, '').replace(/```\s*$/g, '').trim();
        return JSON.parse(cleaned);
    } catch (e) {
        try {
            const fixed = response.replace(/,\s*([\]}])/g, '$1').replace(/```json?\n?/g, '').replace(/```\s*$/g, '').trim();
            return JSON.parse(fixed);
        } catch {
            return null;
        }
    }
}

function deriveMsfPath(filePath) {
    const match = filePath.match(/modules\/(exploits\/windows\/[^.]+)/);
    if (match) return match[1];
    return filePath.replace('.rb', '').replace('modules/', '');
}

// FIX: was 'exploit' (singular), path actually uses 'exploits' (plural)
function deriveServiceCategory(filePath) {
    const match = filePath.match(/modules\/exploits\/windows\/([^/]+)\//);
    if (match) return match[1];
    return 'unknown';
}

function extractMetadataFromRb(content, filePath) {
    const metadata = {
        name: null,
        description: null,
        platform: [],
        arch: [],
        cves: [],
        edb_ids: [],
        port: null,
        targets: [],
        disclosed: null,
        file_path: filePath
    };

    const nameMatch = content.match(/'Name'\s*=>\s*'([^']+)'/);
    if (nameMatch) metadata.name = nameMatch[1];

    const descSingleMatch = content.match(/'Description'\s*=>\s*'([^']+)'/);
    if (descSingleMatch) {
        metadata.description = descSingleMatch[1];
    } else {
        const descMultilineMatch = content.match(/'Description'\s*=>\s*%q\{([^}]*)\}/s);
        if (descMultilineMatch) {
            metadata.description = descMultilineMatch[1].trim();
        }
    }

    const platformMatch = content.match(/'Platform'\s*=>\s*'([^']+)'/);
    if (platformMatch) {
        metadata.platform = [platformMatch[1]];
    } else {
        const platformArrayMatch = content.match(/'Platform'\s*=>\s*\[([^\]]+)\]/);
        if (platformArrayMatch) {
            const platforms = platformArrayMatch[1].match(/'([^']+)'/g);
            if (platforms) metadata.platform = platforms.map(p => p.replace(/'/g, ''));
        }
    }

    const archMatch = content.match(/'Arch'\s*=>\s*\[([^\]]+)\]/);
    if (archMatch) {
        const archs = archMatch[1].match(/ARCH_[A-Z0-9_]+/g);
        if (archs) metadata.arch = archs;
    }

    for (const match of content.matchAll(/\['CVE',\s*'([^']+)'\]/g)) {
        metadata.cves.push(match[1]);
    }

    for (const match of content.matchAll(/\['EDB',\s*'([^']+)'\]/g)) {
        metadata.edb_ids.push(match[1]);
    }

    const portMatch = content.match(/'RPORT'\s*=>\s*(\d+)/);
    if (portMatch) metadata.port = parseInt(portMatch[1], 10);

    const targetsMatch = content.match(/'Targets'\s*=>\s*\[([^\]]*(?:\[[^\]]*\][^\]]*)*)\]/s);
    if (targetsMatch) {
        const targetStrings = targetsMatch[1].match(/\[\s*'([^']+)'/g);
        if (targetStrings) {
            metadata.targets = targetStrings.map(t => {
                const match = t.match(/'([^']+)'/);
                return match ? match[1] : null;
            }).filter(Boolean);
        }
    }

    const disclosureMatch = content.match(/'DisclosureDate'\s*=>\s*'([^']+)'/);
    if (disclosureMatch) metadata.disclosed = disclosureMatch[1];

    return metadata;
}

function heuristicClassification(metadata) {
    const name = (metadata.name || '').toLowerCase();
    const description = (metadata.description || '').toLowerCase();
    const filePath = (metadata.file_path || '').toLowerCase();
    const serviceCategory = deriveServiceCategory(filePath);

    const networkServiceCategories = [
        'smb', 'rdp', 'http', 'https', 'ftp', 'smtp', 'pop', 'imap', 'telnet', 'ssh',
        'vnc', 'mssql', 'mysql', 'postgres', 'oracle', 'redis', 'mongodb', 'snmp',
        'dns', 'ntp', 'ldap', 'rpc'
    ];

    if (networkServiceCategories.includes(serviceCategory)) {
        return {
            replicable: true,
            confidence: 'high',
            reason: `Module targets ${serviceCategory} network service`,
            exclusion_category: null
        };
    }

    if (filePath.includes('fileformat') || filePath.includes('social_engineering')) {
        return {
            replicable: false,
            confidence: 'high',
            reason: 'Module path indicates client-side file format or social engineering exploit',
            exclusion_category: 'client_side_fileformat'
        };
    }

    if (filePath.includes('/local/')) {
        const localIndicators = ['privilege escalation', 'privesc', 'already authenticated', 'existing session'];
        for (const indicator of localIndicators) {
            if (name.includes(indicator) || description.includes(indicator)) {
                return {
                    replicable: false,
                    confidence: 'high',
                    reason: 'Module appears to be a local privilege escalation exploit',
                    exclusion_category: 'local_privesc'
                };
            }
        }
        return {
            replicable: false,
            confidence: 'high',
            reason: 'Module is in local directory requiring local access',
            exclusion_category: 'local_privesc'
        };
    }

    const clientSideIndicators = ['pdf', 'doc', 'word', 'excel', 'office', 'victim', 'email attachment'];
    for (const indicator of clientSideIndicators) {
        if (name.includes(indicator) || description.includes(indicator)) {
            return {
                replicable: false,
                confidence: 'high',
                reason: 'Module requires victim interaction',
                exclusion_category: 'client_side_fileformat'
            };
        }
    }

    const browserIndicators = ['browser', 'chrome', 'firefox', 'internet explorer'];
    for (const indicator of browserIndicators) {
        if (name.includes(indicator) || description.includes(indicator)) {
            return {
                replicable: false,
                confidence: 'high',
                reason: 'Module requires victim to visit a malicious URL in browser',
                exclusion_category: 'client_side_browser'
            };
        }
    }

    if (metadata.port && metadata.port > 0) {
        return {
            replicable: true,
            confidence: 'high',
            reason: `Module targets network service on port ${metadata.port}`,
            exclusion_category: null
        };
    }

    return {
        replicable: true,
        confidence: 'medium',
        reason: 'Appears to be a network-based exploit module but requires verification',
        exclusion_category: null
    };
}

// ============================================================================
// Cache Helpers
// ============================================================================
async function loadCache() {
    // CHECK CLEAR CACHE FLAG
    if (CLEAR_CACHE) {
        console.log('[CACHE] Clear cache flag enabled, starting fresh');
        return { heuristic: {}, llm: {} };
    }
    
    try {
        if (await $`test -f ${CACHE_FILE_PATH}`.quiet().then(() => true).catch(() => false)) {
            const content = await Bun.file(CACHE_FILE_PATH).text();
            const parsed = JSON.parse(content);
            const heuristicCount = LLM_ONLY_MODE ? 0 : Object.keys(parsed.heuristic || {}).length;
            const llmCount = Object.keys(parsed.llm || {}).length;
            console.log(`[CACHE] Loaded ${heuristicCount + llmCount} cached entries (heuristic: ${heuristicCount}, llm: ${llmCount})`);
            return {
                heuristic: parsed.heuristic || {},
                llm: parsed.llm || {}
            };
        }
    } catch (error) {
        console.warn('[CACHE] Failed to load cache, starting fresh:', error.message);
    }
    return { heuristic: {}, llm: {} };
}


async function saveCache(cache) {
    await $`mkdir -p ${CACHE_DIR}`;
    await Bun.write(CACHE_FILE_PATH, JSON.stringify(cache, null, 2));
    console.log(`[CACHE] Saved ${Object.keys(cache.heuristic).length + Object.keys(cache.llm).length} entries to ${CACHE_FILE_PATH}`);
}
// ============================================================================
// LLM Classification Layer
// ============================================================================

function createLLMClient() {
    if (!LLM_API_KEY) throw new Error('LLM_API_KEY environment variable is not set');
    return new OpenAI({
        apiKey: LLM_API_KEY,
        baseURL: LLM_BASE_URL || 'https://api.openai.com/v1'
    });
}

function prepareModuleForLLM(metadata) {
  return {
        id: metadata.msf_path,
        msf_path: metadata.msf_path,
        name: metadata.name,
        service_category: metadata.service_category,
        description: metadata.description || '',
        targets: metadata.targets,
        cves: metadata.cves,
        edb_ids: metadata.edb_ids || [],
        port: metadata.port,
        platform: metadata.platform || [],
        arch: metadata.arch || [],
        disclosed: metadata.disclosed,
        file_path: metadata.file_path
    };
}

const LLM_SYSTEM_PROMPT = `You are a security lab engineer. For each Metasploit Windows exploit module, determine if it can POTENTIALLY be reproduced in a VM lab environment. You are performing INITIAL filtering only - a downstream scenario builder will research software provisioning details. Respond ONLY with a valid JSON array. Schema: { "id": <same as input>, "replicable": true | false, "confidence": "high" | "medium" | "low", "reason": "<one sentence>", "access_type": "initial_foothold" | "privilege_escalation" | "lateral_movement" | "client_side" | "unsupported", "provisioning_complexity": "standard" | "third_party_software" | "service_configuration" }

### OUTPUT SCHEMA
Each object must contain:
{
  "id": <same as input index>,
  "replicable": true | false,
  "confidence": "high" | "medium" | "low",
  "reason": "<one sentence>",
  "access_type": "initial_foothold" | "privilege_escalation" | "lateral_movement" | "client_side" | "unsupported",
  "provisioning_complexity": "standard" | "third_party_software" | "service_configuration",
  "extracted_metadata": {
    "vendor": "string or null",
    "product": "string or null", 
    "tested_version": "string or null",
    "protocol_hint": "string or null (e.g., 'UDP/1926', 'TCP/8192')",
    "platform_notes": "string or null (e.g., 'Windows 7-10', 'Server 2012-2022')"
    "disclosure_date": "string or null (extract from 'DisclosureDate' field if present)"
  }
}

### CLASSIFICATION RULES
Mark replicable: true if ALL apply:
- Targets Windows OS (not hardware/IoT/firmware/non-Windows)
- Does NOT require victim interaction (no clicking, opening files, visiting URLs, initiating connections)
- Can achieve remote code execution or shell over network (any attack stage)

Mark replicable: false ONLY if:
- "client_side": requires victim interaction (browser, file open, social engineering)
- "unsupported": targets physical hardware, IoT, firmware, embedded/ICS/SCADA, non-Windows OS

Set access_type:
- "initial_foothold": achieves first remote access without credentials
- "privilege_escalation": requires existing local access/session to escalate
- "lateral_movement": requires valid credentials to move between systems
- "client_side": requires victim interaction
- "unsupported": hardware/IoT/firmware/non-Windows

Set provisioning_complexity:
- "standard": Built-in Windows service (SMB, RDP, HTTP, IIS, etc.)
- "third_party_software": Requires installing additional software (Novell, SAP, SCADA, VPN, etc.)
- "service_configuration": Requires enabling/configuring Windows features (RRAS, IIS roles, etc.)


### METADATA EXTRACTION RULES
For extracted_metadata fields, extract from description ONLY if explicitly stated:
- vendor: Look for "by <Vendor>", "from <Vendor>", "developed by <Vendor>"
- product: Look for "the <Product> server/service", "utilizes <Product>", "targets <Product>"
- tested_version: Look for "Tested against <X.Y.Z>", "version <X.Y.Z>", "v<X.Y.Z>"
- protocol_hint: Look for port numbers, "UDP/TCP <port>", "binds to <port>"
- platform_notes: Look for OS version ranges like "Windows 7-10", "Server 2012-2022"
- disclosure_date: Extract from module's 'DisclosureDate' field or description phrases like "disclosed on <date>"

If a field cannot be confidently extracted, set it to null. Do NOT hallucinate values.

Use confidence: "low" only for genuinely ambiguous cases.
Ignore modules not targeting Windows.
No markdown, no explanation outside JSON.`;

async function classifySingleWithLLM(module) {
    const client = createLLMClient();
    const input = prepareModuleForLLM(module);

    await rateLimitedDelay();
    try {
        const response = await client.chat.completions.create({
            model: LLM_MODEL,
            messages: [
                { role: 'system', content: LLM_SYSTEM_PROMPT },
                { role: 'user', content: JSON.stringify([input]) }
            ],
            temperature: 0
        });

        const content = response.choices[0].message.content;
        const result = parseLLMJson(content);
        if (!result) throw new Error('Failed to parse LLM JSON response');

        // Handle array or single-object responses
        const results = Array.isArray(result) ? result : 
                       result.modules || result.results || result.classifications || 
                       (typeof result.replicable !== 'undefined' ? [{ ...result, id: input.id }] : []);

        // Merge extracted_metadata into each result
        return results.map(r => {
            const base = {
                msf_path: input.msf_path,
                name: input.name,
                service_category: input.service_category,
                description: input.description,
                platform: input.platform,
                arch: input.arch,
                cves: input.cves,
                edb_ids: [],  // Preserve from original metadata if needed
                port: input.port,
                targets: input.targets,
                disclosed: input.disclosed,
                file_path: input.file_path || null,
                // Classification fields
                replicable: r.replicable,
                confidence: r.confidence,
                reason: r.reason,
                access_type: r.access_type,
                provisioning_complexity: r.provisioning_complexity,
                exclusion_category: r.access_type === 'client_side' ? 'client_side' : 
                                   r.access_type === 'privilege_escalation' ? 'local_privesc' : null,
                extracted_metadata: r.extracted_metadata || {
                    vendor: null,
                    product: null,
                    tested_version: null,
                    protocol_hint: null,
                    platform_notes: null
                }
            };
            return base;
        });

    } catch (error) {
        console.error(`[LLM] Classification failed for ${module.msf_path}: ${error.message}`);
        return [{
            msf_path: module.msf_path,
            name: module.name,
            service_category: module.service_category,
            description: module.description,
            platform: module.platform,
            arch: module.arch,
            cves: module.cves,
            port: module.port,
            targets: module.targets,
            file_path: module.file_path,
            replicable: null,
            confidence: 'error',
            reason: `LLM classification failed: ${error.message}`,
            access_type: null,
            provisioning_complexity: null,
            exclusion_category: null,
            extracted_metadata: {
                vendor: null,
                product: null,
                tested_version: null,
                protocol_hint: null,
                platform_notes: null
            }
        }];
    }
}

async function classifyUncertainModulesWithLLM(uncertainModules, cache) {
    const modulesToProcess = uncertainModules.filter(m => !cache.llm[m.msf_path]);

    if (modulesToProcess.length === 0) {
        console.log('[LLM] No uncertain modules to classify');
        return [];
    }
    
    const modeLabel = LLM_ONLY_MODE ? 'ALL modules (LLM-only mode)' : 'uncertain modules';
    console.log(`[LLM] Classifying ${modulesToProcess.length} ${modeLabel}...`);
    
    const results = []; 
    let processedCount = 0;
    
    for (let i = 0; i < modulesToProcess.length; i++) {
        const module = modulesToProcess[i];
        console.log(`[LLM] Processing module ${i + 1}/${modulesToProcess.length}: ${module.msf_path}`);
        
        const classified = await classifySingleWithLLM(module);
        const result = classified[0];  // We process one at a time
        
        // Only cache if classification succeeded
        if (result.confidence !== 'error' && result.replicable !== null) {
            // ← Store the FULL enriched object in cache
            cache.llm[module.msf_path] = result;
            results.push(result);
        } else {
            console.warn(`[LLM] Skipping cache for failed module: ${module.msf_path}`);
        }
        
        processedCount++;
        if (processedCount % BATCH_SIZE === 0) {
            await saveCache(cache);
            console.log(`[CACHE] Checkpoint saved (${processedCount}/${modulesToProcess.length})`);
        }
    }
    
    console.log(`[LLM] Classification complete for ${modulesToProcess.length} modules`);
    return results;
}

// ============================================================================
// Main Operations
// ============================================================================

async function sparseCloneMetasploit() {
    console.log('[CLONE] Checking for Metasploit framework...');

    const exists = await $`test -d ${METASPLOIT_DIR}`.quiet().then(() => true).catch(() => false);
    if (exists) {
        console.log('[CLONE] Metasploit framework already exists, skipping clone');
        return;
    }

    console.log('[CLONE] Performing sparse clone of Metasploit framework...');
    try {
        await $`git clone --depth=1 --filter=blob:none --sparse https://github.com/rapid7/metasploit-framework.git`;
        await $`git -C ${METASPLOIT_DIR} sparse-checkout set ${WINDOWS_EXPLOITS_PATH}`;
        console.log('[CLONE] Sparse clone completed successfully');
    } catch (error) {
        console.error('[CLONE] Error during sparse clone:', error.message);
        throw error;
    }
}

async function findRbFiles(dir) {
    const glob = new Bun.Glob('**/*.rb');
    const files = [];
    for await (const file of glob.scan(dir)) {
        files.push(path.join(dir, file));
    }
    return files;
}

async function parseRubyFiles(rbFiles, cache) {
    const results = [];
    let parseErrors = 0;
    const uncertainModules = [];
    
    // Combine keys for quick lookup
    const cachedPaths = new Set([
        ...Object.keys(cache.heuristic), 
        ...Object.keys(cache.llm)
    ]);

    console.log(`[PARSE] Processing ${rbFiles.length} Ruby files...`);
    for (const filePath of rbFiles) {
        const msfPath = deriveMsfPath(filePath);
        
        // CHECK CACHE: Skip if already processed (Heuristic OR LLM)
        if (cachedPaths.has(msfPath)) {
            const cachedData = cache.heuristic[msfPath] || cache.llm[msfPath];
            results.push(cachedData);
            continue; 
        }

        try {
            const content = await Bun.file(filePath).text();
            const metadata = extractMetadataFromRb(content, filePath);
            metadata.msf_path = msfPath;
            metadata.service_category = deriveServiceCategory(filePath);

            if (LLM_ONLY_MODE) {
                metadata.replicable = null;
                metadata.confidence = 'pending';
                metadata.reason = 'Pending LLM classification';
                metadata.exclusion_category = null;
                metadata.provisioning_complexity = null;
                metadata.extracted_metadata = null; 
                uncertainModules.push(metadata);
            } else {
                // Use heuristic classification
                const classification = heuristicClassification(metadata);
                metadata.replicable = classification.replicable;
                metadata.confidence = classification.confidence;
                metadata.reason = classification.reason;
                metadata.exclusion_category = classification.exclusion_category;
                
                // Cache heuristic results (High AND Medium)
                if (['high', 'medium'].includes(classification.confidence)) {
                    cache.heuristic[msfPath] = metadata;
                }
                if (classification.confidence === 'medium') {
                    uncertainModules.push(metadata);
                }
            }
            
            results.push(metadata);
        } catch (error) {
            console.error(`[PARSE] Error parsing ${filePath}: ${error.message}`);
            parseErrors++;
        }
    }
    return { results, parseErrors, uncertainModules };
}

function calculateAndLogStatistics(results) {
    const total = results.length;
    const replicable = results.filter(m => m.replicable === true);
    const notReplicable = results.filter(m => m.replicable === false);

    const byCategory = {};
    for (const mod of notReplicable) {
        const cat = mod.exclusion_category || 'unknown';
        byCategory[cat] = (byCategory[cat] || 0) + 1;
    }

    const byAccessType = {};
    for (const mod of results) {
        const type = mod.access_type || (mod.replicable ? 'initial_foothold' : 'unknown');
        byAccessType[type] = (byAccessType[type] || 0) + 1;
    }


    const windowsCount = results.filter(m =>
        m.platform?.some(p => p.toLowerCase().includes('win'))
    ).length;
    const linuxCount = results.filter(m =>
        m.platform?.some(p => p.toLowerCase().includes('linux'))
    ).length;

    const replicablePct = total > 0 ? ((replicable.length / total) * 100).toFixed(1) : '0.0';
    const notReplicablePct = total > 0 ? ((notReplicable.length / total) * 100).toFixed(1) : '0.0';

    console.log('\n' + '='.repeat(60));
    console.log('METASPLOIT WINDOWS EXPLOIT MODULE ANALYSIS');
    console.log('='.repeat(60));
    console.log(`[RESULT] Total Windows exploit modules: ${total}`);
    console.log(`[RESULT] VM-replicable (initial foothold): ${replicable.length} (${replicablePct}%)`);
    console.log(`[RESULT] NOT replicable: ${notReplicable.length} (${notReplicablePct}%)`);
    console.log('\nBreakdown of non-replicable by category:');
    for (const [category, count] of Object.entries(byCategory).sort((a, b) => b[1] - a[1])) {
        console.log(`  ${category}: ${count}`);
    }
    console.log('\n' + '-'.repeat(60));
    console.log('PLATFORM BREAKDOWN');
    console.log('-'.repeat(60));
    console.log(`[PLATFORM] Windows-focused modules: ${windowsCount}`);
    console.log(`[PLATFORM] Linux-focused modules: ${linuxCount}`);
    console.log(`[PLATFORM] Mixed/Other: ${total - windowsCount - linuxCount}`);
    console.log('\n' + '='.repeat(60));
    console.log('ANALYSIS COMPLETE');
    console.log('='.repeat(60) + '\n');

    console.log('\nBreakdown by access type:');
    for (const [type, count] of Object.entries(byAccessType).sort((a, b) => b[1] - a[1])) {
        console.log(`  ${type}: ${count}`);
    }

    const byComplexity = {};
    for (const mod of results) {
        const complexity = mod.provisioning_complexity || 'unknown';
        byComplexity[complexity] = (byComplexity[complexity] || 0) + 1;
    }
    console.log('\nBreakdown by provisioning complexity:');
    for (const [complexity, count] of Object.entries(byComplexity).sort((a, b) => b[1] - a[1])) {
        console.log(`  ${complexity}: ${count}`);
    }

    return { total, replicable: replicable.length, notReplicable: notReplicable.length, windowsCount, linuxCount, byCategory, byComplexity };
}

async function main() {
    console.log('Metasploit Module Metadata Extractor');
    console.log('=====================================\n');
    await sparseCloneMetasploit();
    
    // 1. LOAD CACHE
    const cache = await loadCache();
    if (LLM_ONLY_MODE) {
        console.log('[MODE] LLM-only mode enabled - bypassing heuristic classification');
        cache.heuristic = {}; // Ignore heuristic cache, rely on LLM cache only
    }

    const exploitsDir = path.join(METASPLOIT_DIR, WINDOWS_EXPLOITS_PATH);
    console.log(`[SCAN] Scanning ${exploitsDir}...`);
    const rbFiles = await findRbFiles(exploitsDir);
    console.log(`[SCAN] Found ${rbFiles.length} .rb files under ${WINDOWS_EXPLOITS_PATH}/`);
    
    // 2. PASS CACHE TO PARSER
    const { results, parseErrors, uncertainModules } = await parseRubyFiles(rbFiles, cache);
    console.log(`[PARSE] Uncertain modules identified: ${uncertainModules.length}`);
    
    if (uncertainModules.length > 0 && LLM_API_KEY) {
        // 3. PASS CACHE TO LLM CLASSIFIER
        await classifyUncertainModulesWithLLM(uncertainModules, cache);

        for (let i = 0; i < results.length; i++) {
            const msfPath = results[i].msf_path;
            if (cache.llm[msfPath]) {
                results[i] = cache.llm[msfPath];  // Replace stale object with enriched one
            }
        }
    } else if (uncertainModules.length > 0 && !LLM_API_KEY) {
        console.log('[LLM] API key not set, keeping heuristic classifications for uncertain modules');
    }
    
    const stats = calculateAndLogStatistics(results);
    await $`mkdir -p ${OUTPUT_DIR}`;
    
    // Existing output
    const outputPath = path.join(OUTPUT_DIR, 'filtered_modules.json');
    await Bun.write(outputPath, JSON.stringify(results, null, 2));
    console.log(`[OUTPUT] Written: ${outputPath}`);
    
    // Existing summary
    const summaryPath = path.join(OUTPUT_DIR, 'analysis_summary.json');
    await Bun.write(summaryPath, JSON.stringify({
        generated_at: new Date().toISOString(),
        statistics: stats,
        provisioning_complexity: stats.byComplexity,
        llm_classification: {
            uncertain_modules_classified: LLM_API_KEY ? uncertainModules.length : 0,
            api_key_set: !!LLM_API_KEY
        }
    }, null, 2));
    console.log(`[OUTPUT] Written: ${summaryPath}`);

    // 4. SAVE CACHE (After everything is done)
    await saveCache(cache);

    return results;
}

export {
    extractMetadataFromRb,
    heuristicClassification,
    deriveMsfPath,
    deriveServiceCategory,
    sparseCloneMetasploit,
    findRbFiles,
    parseRubyFiles,
    calculateAndLogStatistics,
    classifyUncertainModulesWithLLM,
    classifySingleWithLLM,
    prepareModuleForLLM,
    createLLMClient,
    LLM_SYSTEM_PROMPT
};

main().catch(console.error);