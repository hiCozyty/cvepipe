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
const CLEAR_CACHE = false;
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
        msf_path: metadata.msf_path,
        name: metadata.name,
        service_category: metadata.service_category, // now correctly populated
        description: metadata.description || '',
        targets: metadata.targets,
        cves: metadata.cves,
        port: metadata.port
    };
}

const LLM_SYSTEM_PROMPT = `You are a security lab engineer. For each Metasploit Windows exploit module, determine if it can achieve INITIAL REMOTE FOOTHOLD in a standard VM lab: attacker Kali VM targeting a Windows Server/Desktop VM over a network, with NO user interaction on the target. Respond ONLY with a valid JSON array. Schema: { "id": <same as input>, "replicable": true | false, "confidence": "high" | "medium" | "low", "reason": "<one sentence>", "access_type": "initial_foothold" | "privilege_escalation" | "lateral_movement" | "client_side" | "unsupported" } 

Mark replicable: true ONLY if ALL apply:
- Targets a network service listening on Windows (SMB, RDP, HTTP, RPC, etc.)
- Achieves initial remote code execution or shell WITHOUT valid credentials
- Requires NO victim interaction (no clicking, opening files, visiting URLs)
- Does NOT require third-party software uncommon on standard Windows VMs

Mark replicable: false and set access_type accordingly:
- "privilege_escalation": requires existing local access/session to escalate
- "lateral_movement": requires valid credentials to move laterally (not initial foothold)
- "client_side": requires victim interaction (browser visit, file open, social engineering)
- "unsupported": targets hardware/IoT/firmware/physical/non-Windows

Use confidence: "low" only for genuinely ambiguous cases. 
Ignore modules not targeting Windows. 
No markdown, no explanation outside JSON.`;

async function classifySingleWithLLM(module) {
    const client = createLLMClient();
    const input = prepareModuleForLLM(module);

    console.log(`[LLM] Input: ${JSON.stringify(input, null, 2)}`);

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
        console.log(`[LLM] Raw response: ${content}`);

        const result = JSON.parse(content);

        if (Array.isArray(result)) return result;
        if (result.modules && Array.isArray(result.modules)) return result.modules;
        if (result.results && Array.isArray(result.results)) return result.results;
        if (result.classifications && Array.isArray(result.classifications)) return result.classifications;
        if (typeof result.replicable !== 'undefined') return [{ ...result, id: 0 }];

        throw new Error(`Unexpected LLM response format. Keys: ${Object.keys(result).join(', ')}`);
    } catch (error) {
        console.error(`[LLM] Classification failed for ${module.msf_path}: ${error.message}`);
        return [{
            id: 0,
            replicable: null,
            confidence: 'error',
            reason: `LLM classification failed: ${error.message}`,
            exclusion_category: null
        }];
    }
}

async function classifyUncertainModulesWithLLM(uncertainModules, cache) {
    // Filter out anything already in LLM cache (safety check)
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
        const [result] = await classifySingleWithLLM(module);
        
        // only cache if classification succeeded (NOT error/null)
        if (result.confidence !== 'error' && result.replicable !== null) {
            module.replicable = result.replicable;
            module.confidence = result.confidence;
            module.reason = result.reason;
            module.access_type = result.access_type;
            module.exclusion_category = result.access_type === 'client_side' ? 'client_side' :  result.access_type === 'privilege_escalation' ? 'local_privesc' : null;
            
            cache.llm[module.msf_path] = module;  // ← Only cache successes
            results.push(module);
        } else {
            console.warn(`[LLM] Skipping cache for failed module: ${module.msf_path}`);
            // Don't cache errors - they'll be retried on next run
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
                // Skip heuristic, send ALL to LLM
                metadata.replicable = null;
                metadata.confidence = 'pending';
                metadata.reason = 'Pending LLM classification';
                metadata.exclusion_category = null;
                uncertainModules.push(metadata); // ALL modules go to LLM
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

    return { total, replicable: replicable.length, notReplicable: notReplicable.length, windowsCount, linuxCount, byCategory };
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