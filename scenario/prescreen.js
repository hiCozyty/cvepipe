#!/usr/bin/env bun

/**
 * Exploit Prescreen: VM Reproducibility Research Agent
 * Filters exploits and performs agentic deep research via SearXNG + LLM
 * 
 * NOW USES: Pre-extracted metadata from Metasploit extractor (no regex needed)
 */

import { $ } from 'bun';
import { JSDOM, VirtualConsole } from 'jsdom';
import { Readability } from '@mozilla/readability';
import { OpenAI } from 'openai';
import Bottleneck from 'bottleneck';

const crypto = globalThis.crypto

// ============================================================================
// Configuration
// ============================================================================

const SEARXNG_ENDPOINT = process.env.SEARXNG_ENDPOINT;
const SEARXNG_TIMEOUT = parseInt(process.env.SEARXNG_TIMEOUT || '3000', 10);
const MAX_RESEARCH_DEPTH = 5; //maximum loop number
const RESULTS_PER_SEARCH = 10;

const OUTPUT_DIR = './data/prescreen';
const CACHE_RESULTS = true;
const DEBUG_LLM = true;

const LLM_API_KEY =  process.env.LLM_API_KEY;
const LLM_BASE_URL = process.env.LLM_BASE_URL;
const LLM_MODEL = process.env.LLM_MODEL;
const LLM_TEMPERATURE = 0;
const LLM_MAX_TOKENS = 16384;

const EXTRACT_TOP_N = 10;              // Results from SearXNG to consider
const EXTRACT_CONTENT_TOP_N = 7;      // URLs to actually fetch full content from
const CONTENT_PREVIEW_CHARS = 15000;    // Chars of extracted content per page in LLM prompt
const MIN_ARTICLE_LENGTH = 200;       // Skip pages shorter than this
const MAX_CONTENT_PER_STAGE = 80000;   // Hard cap on total extracted chars sent to LLM

const INPUT_FILE = './output/test.json';
const OUTPUT_FILE = './output/prescreen_results.json';

const TEST_MODE = {
    enabled: true,           // Set to true to test one stage at a time
    stopAfterStage: 'stage4', // 'stage1' | 'stage2' | 'stage3' | 'stage4' | null
    verboseLogging: true,    // Extra logs for input/output inspection
    prettyPrint: true,       // JSON.stringify with indentation for logs
};

function log(...args) {
    console.log(...args);
}
function parseLLMJson(response) {
    if (!response) throw new Error('Empty response');
    
    // Step 1: Remove markdown code fences (```json, ```, etc.)
    let cleaned = response.replace(/^```(?:json)?\s*|\s*```$/g, '').trim();
    
    // Step 2: Find the first { or [ and last } or ] to extract JSON bounds
    const startBrace = cleaned.indexOf('{');
    const endBrace = cleaned.lastIndexOf('}');
    const startBracket = cleaned.indexOf('[');
    const endBracket = cleaned.lastIndexOf(']');
    
    // Prefer object over array if both present
    let startIdx = Math.max(startBrace, startBracket);
    let endIdx = Math.max(endBrace, endBracket);
    
    // If we found object braces, use those
    if (startBrace !== -1 && endBrace !== -1 && endBrace > startBrace) {
        startIdx = startBrace;
        endIdx = endBrace;
    }
    // Else if we found array brackets
    else if (startBracket !== -1 && endBracket !== -1 && endBracket > startBracket) {
        startIdx = startBracket;
        endIdx = endBracket;
    }
    // Else fail
    else {
        throw new Error(`No valid JSON bounds found in response: ${response.substring(0, 100)}...`);
    }
    
    // Extract and parse
    const jsonStr = cleaned.substring(startIdx, endIdx + 1).trim();
    return JSON.parse(jsonStr);
}
async function appendToAggregatedResults(entryId, result, outputFile = OUTPUT_FILE) {
    const fileRef = Bun.file(outputFile);
    
    // Read existing results or initialize
    let aggregated = { 
        processed: 0, 
        timestamp: new Date().toISOString(), 
        results: {}  // ← OBJECT, not array
    };
    
    if (await fileRef.exists()) {
        try {
            aggregated = await fileRef.json();
            // Migrate old array-based results to object if needed
            if (Array.isArray(aggregated.results)) {
                console.log(`  ↻ Migrating ${aggregated.results.length} array results to object keys`);
                const migrated = {};
                for (const r of aggregated.results) {
                    const key = r.entry?.msf_path || r.entryId || crypto.randomUUID();
                    migrated[key] = r;
                }
                aggregated.results = migrated;
            }
            // Ensure results is an object
            if (typeof aggregated.results !== 'object' || aggregated.results === null || Array.isArray(aggregated.results)) {
                aggregated.results = {};
            }
        } catch (e) {
            console.warn(`  ⚠ Failed to read existing results: ${e.message}. Starting fresh.`);
            aggregated.results = {};
        }
    }
    
    // Use entryId (msf_path) as the KEY
    const key = entryId;  // e.g., "exploits/windows/vnc/winvnc_http_get"
    
    // Update or add result
    if (aggregated.results[key]) {
        console.log(`  ↻ Updating entry: ${key}`);
        aggregated.results[key] = { ...aggregated.results[key], ...result, updated_at: new Date().toISOString() };
    } else {
        console.log(`  ➕ Adding entry: ${key}`);
        aggregated.results[key] = { ...result, added_at: new Date().toISOString() };
    }
    
    // Update metadata
    aggregated.processed = Object.keys(aggregated.results).length;
    aggregated.last_updated = new Date().toISOString();
    
    // Atomic write: write to temp file, then rename
    const tempFile = `${outputFile}.tmp.${Date.now()}`;
    await Bun.write(tempFile, JSON.stringify(aggregated, null, 2));
    await $`mv ${tempFile} ${outputFile}`;  // Atomic rename
    
    return aggregated;
}
function logJSON(label, data, level = 'info') {
    if (!TEST_MODE.verboseLogging) return;
    const prefix = level === 'error' ? '✗' : level === 'warn' ? '⚠' : '✓';
    console.log(`\n[${prefix} ${label}]`);
    console.log(TEST_MODE.prettyPrint 
        ? JSON.stringify(data, null, 2).slice(0, 2000) + (JSON.stringify(data).length > 2000 ? '...[truncated]' : '')
        : data
    );
}

function logTaskExecution(task, result, context) {
    if (!TEST_MODE.verboseLogging) return;
    console.log(`\n  ┌─ Task: ${task.type}`);
    console.log(`  │ Query: ${task.query?.substring(0, 120)}${task.query?.length > 120 ? '...' : ''}`);
    console.log(`  │ Status: ${task.status}`);
    if (task.result?.success !== undefined) {
        console.log(`  │ Search results: ${task.result.results?.length || 0} found`);
        task.result.results?.slice(0, 3).forEach((r, i) => {
            console.log(`  │   [${i+1}] ${r.title?.substring(0, 60)}... → ${r.url}`);
        });
    }
    if (task.result?.type === 'open_ended') {
        console.log(`  │ Open-ended sub-queries: ${task.result.subQueries?.length || 0}`);
    }
    console.log(`  └─ Visited URLs this stage: ${context.visitedUrls.size}`);
}

// Rate limiting: 1 request per 10s 
const searxngLimiter = new Bottleneck({ 
  minTime: 10_000,    
  maxConcurrent: 1 
});
const llmLimiter = new Bottleneck({ minTime: 5_000, maxConcurrent: 1 });
let lastRequestTime = 0;

async function rateLimitedDelay() {
    const now = Date.now();
    const elapsed = now - lastRequestTime;
    if (elapsed < 10000) {
        await new Promise(resolve => setTimeout(resolve, 10000 - elapsed));
    }
    lastRequestTime = Date.now();
}


// ===== CORE DATA STRUCTURES =====

class Task {
    constructor({ type, query, depends_on = [], metadata = {}, priority = 0 }) {
        this.id = crypto.randomUUID();
        this.type = type; // 'web_search' | 'reasoning' | 'archive_lookup' | 'open_ended'
        this.query = query;
        this.depends_on = depends_on; // task IDs this depends on
        this.metadata = metadata;
        this.priority = priority;
        this.status = 'pending';
        this.result = null;
        this.error = null;
        this.attempts = 0;
    }
}

class StageContext {
    constructor(entryId, stageName) {
        this.entryId = entryId;
        this.stageName = stageName;
        this.tasks = new Map();
        this.completedTasks = new Map();
        this.visitedUrls = new Set(); // Track URLs to avoid re-searching
        this.confidence = 0;
        this.confidenceThreshold = 0.7;
        this.loopCount = 0;
        this.maxLoops = MAX_RESEARCH_DEPTH;
        this.synthesizedOutput = null;
        this.errors = [];
    }
    
    addTask(task) {
        this.tasks.set(task.id, task);
        return task.id;
    }
    
    markVisited(url) {
        if (url) this.visitedUrls.add(url.toLowerCase().trim());
    }
    
    isVisited(url) {
        return url && this.visitedUrls.has(url.toLowerCase().trim());
    }
    
    canProceed() {
        // Exit loop if confidence met OR max loops reached
        return this.confidence >= this.confidenceThreshold || 
               this.loopCount >= this.maxLoops;
    }
    
    getPendingTasks() {
        // Return tasks that are pending AND whose dependencies are satisfied
        return Array.from(this.tasks.values())
            .filter(t => t.status === 'pending')
            .filter(t => t.depends_on.every(depId => {
                const dep = this.completedTasks.get(depId);
                return dep && dep.status === 'completed';
            }))
            .sort((a, b) => b.priority - a.priority); // Higher priority first
    }
}

class EntryContext {
    constructor(entry) {
        this.entryId = entry.msf_path || `entry_${crypto.randomUUID().slice(0,8)}`;
        this.rawEntry = entry;
        // Isolated context per stage
        this.stages = {
            stage1: new StageContext(this.entryId, 'understand_vulnerability'),
            stage2: new StageContext(this.entryId, 'understand_software'),
            stage3: new StageContext(this.entryId, 'classify_software'),
            stage4: new StageContext(this.entryId, 'find_downloads')
        };
        this.currentStage = 'stage1';
        this.finalResult = null;
        // Per-entry checkpoint for crash recovery
        this.checkpointFile = `${OUTPUT_DIR}/checkpoints/${this.entryId.replace(/\//g, '_')}.checkpoint.json`;
    }
    
    async saveCheckpoint () {
        const checkpoint = {
            entryId: this.entryId,
            rawEntry: this.rawEntry,
            stages: Object.fromEntries(
                Object.entries(this.stages).map(([key, ctx]) => [
                    key,
                    {
                        stageName: ctx.stageName,
                        synthesizedOutput: ctx.synthesizedOutput,
                        confidence: ctx.confidence,
                        loopCount: ctx.loopCount,
                        visitedUrls: Array.from(ctx.visitedUrls),
                        errors: ctx.errors
                        // Note: We don't save individual tasks to keep checkpoint small
                    }
                ])
            ),
            currentStage: this.currentStage,
            finalResult: this.finalResult,
            lastUpdated: new Date().toISOString()
        };
        await Bun.write(this.checkpointFile, JSON.stringify(checkpoint, null, 2));
    }
    
    async loadCheckpoint() {
        const fileRef = Bun.file(this.checkpointFile);
        if (!(await fileRef.exists())) return false;

        try {
            const checkpoint = await fileRef.json(); 
            this.currentStage = checkpoint.currentStage;
            this.finalResult = checkpoint.finalResult;
            
            // Restore stage state (but not individual tasks - we'll regenerate)
            for (const [key, stageData] of Object.entries(checkpoint.stages)) {
                const ctx = this.stages[key];
                ctx.synthesizedOutput = stageData.synthesizedOutput;
                ctx.confidence = stageData.confidence;
                ctx.loopCount = stageData.loopCount;
                ctx.visitedUrls = new Set(stageData.visitedUrls);
                ctx.errors = stageData.errors;
            }
            console.log(`  ↻ Resumed from checkpoint`);
            return true;
        } catch (e) {
            console.error(`  ✗ Failed to load checkpoint: ${e.message}`);
            return false;
        }
    }
}

// ===== LLM & SEARCH INFRASTRUCTURE =====

async function callLLM(prompt, systemPrompt = "You are a security research assistant.") {
    await rateLimitedDelay();
    
    const client = new OpenAI({
        apiKey: LLM_API_KEY,
        baseURL: LLM_BASE_URL,
    });
    
    try {
        const response = await llmLimiter.schedule(() =>
            client.chat.completions.create({
                model: LLM_MODEL,
                messages: [
                    { role: "system", content: systemPrompt },
                    { role: "user", content: prompt }
                ],
                temperature: LLM_TEMPERATURE,
                max_tokens: LLM_MAX_TOKENS,
            })
        );
        
        const content = response.choices[0].message.content;
        if (DEBUG_LLM) {
            console.log(`  [LLM] ${content.substring(0, 200)}...`);
        }
        return content;
    } catch (error) {
        console.error('  [LLM ERROR]', error.message);
        throw error;
    }
}

async function executeWebSearch(query, context) {
    try {
        const url = `${SEARXNG_ENDPOINT}/search?format=json&q=${encodeURIComponent(query)}&results=${RESULTS_PER_SEARCH}`;
        const response = await searxngLimiter.schedule(() => 
            fetch(url, { signal: AbortSignal.timeout(SEARXNG_TIMEOUT) })
        );
        
        if (!response.ok) throw new Error(`Search failed: ${response.status}`);
        
        const results = await response.json();
        
        // Filter out already-visited URLs
        const filtered = results.results?.filter?.(r => r?.url && !context.isVisited(r.url)) || [];
        
        // Mark URLs as visited
        filtered.forEach(r => context.markVisited(r.url));
        
        return {
            success: true,
            query,
            results: filtered.slice(0, EXTRACT_TOP_N),
            totalFound: results.number_of_results,
            timestamp: new Date().toISOString()
        };
    } catch (error) {
        return {
            success: false,
            query,
            error: error.message,
            timestamp: new Date().toISOString()
        };
    }
}

async function extractPageContent(url) {
    try {
        const response = await fetch(url, { 
            signal: AbortSignal.timeout(10000),
            headers: { 'User-Agent': 'Mozilla/5.0 (Security Research Bot)' }
        });
        
        if (!response.ok) return null;
        
        const html = await response.text();
        const dom = new JSDOM(html, { virtualConsole: new VirtualConsole() });
        const reader = new Readability(dom.window.document);
        const article = reader.parse();
        
        if (!article || article.textContent?.length < MIN_ARTICLE_LENGTH) return null;
        
        return {
            url,
            title: article.title,
            content: article.textContent,
            excerpt: article.excerpt,
            length: article.textContent.length
        };
    } catch (error) {
        return null;
    }
}

async function executeTask(task, context) {
    task.status = 'running';
    task.attempts++;
    
    try {
        switch (task.type) {
            case 'web_search':
                task.result = await executeWebSearch(task.query, context);
                break;
                
            case 'reasoning':
                task.result = await callLLM(task.query, task.metadata.systemPrompt);
                break;
                
            case 'archive_lookup':
                // Specialized search for archive.org and legacy software sites
                const archiveQuery = `site:web.archive.org OR site:oldversion.com OR site:filehippo.com ${task.query}`;
                task.result = await executeWebSearch(archiveQuery, context);
                break;
                
            case 'open_ended':
                // Spawn targeted sub-queries based on research goal
                const subQueries = await callLLM(
                    `Research goal: "${task.query}". Generate 3-5 specific, targeted search queries. Return one per line, no numbering.`,
                    "You are a research query optimizer."
                );
                
                const queries = subQueries.split('\n')
                    .map(q => q.trim())
                    .filter(q => q && q.length > 10);
                
                const results = await Promise.all(
                    queries.map(q => executeWebSearch(q, context))
                );
                
                task.result = {
                    type: 'open_ended',
                    goal: task.query,
                    subQueries: queries,
                    results: results.filter(r => r?.success)
                };
                break;
                
            default:
                throw new Error(`Unknown task type: ${task.type}`);
        }
        
        task.status = 'completed';
        return task.result;
    } catch (error) {
        task.status = 'failed';
        task.error = error.message;
        context.errors.push({ 
            taskId: task.id, 
            type: task.type,
            error: error.message, 
            timestamp: new Date().toISOString() 
        });
        throw error;
    }
}

// ===== STAGE 1: UNDERSTAND VULNERABILITY =====

const STAGE1_PROMPT = `You analyze vulnerabilities from minimal data. Focus on:
- Vulnerability type (buffer overflow, logic flaw, etc.)
- Affected component (web server, client, protocol handler)
- Trigger mechanism (specific request, file, interaction)
- Preconditions (config, auth, environment)
- Impact (RCE, DoS, privilege escalation)

Be technical and precise. Avoid speculation.`;

async function stage1Planner(entry, context) {
    const tasks = [];
    const name = entry.name || 'unknown';
    const year = entry.extracted_metadata?.disclosure_date?.split('-')[0] || '';
    
    // Initial recon search
    tasks.push(new Task({
        type: 'web_search',
        query: `"${name}" vulnerability ${year}`,
        priority: 10,
        metadata: { purpose: 'initial_recon' }
    }));
    
    // Reasoning to form hypotheses
    tasks.push(new Task({
        type: 'reasoning',
        query: `Exploit: "${name}". Based on name alone, what vulnerability type is this? What component? What triggers it?`,
        priority: 9,
        metadata: { systemPrompt: STAGE1_PROMPT }
    }));
    
    return tasks;
}

async function stage1Synthesizer(entry, context) {
    const searchResults = Array.from(context.completedTasks.values())
        .filter(t => t.type === 'web_search' && t.result?.success)
        .flatMap(t => t.result.results || []);
    
    const reasoning = Array.from(context.completedTasks.values())
        .filter(t => t.type === 'reasoning')
        .map(t => t.result)
        .join('\n---\n');
    
    // Extract content from top URLs
    const urls = searchResults.slice(0, EXTRACT_CONTENT_TOP_N).map(r => r.url).filter(Boolean);
    const content = await Promise.all(urls.map(u => extractPageContent(u)));
    

    // Filter valid content and apply total char cap
    const validContent = content.filter(c => c?.content?.length >= MIN_ARTICLE_LENGTH);
    let totalChars = 0;
    const truncatedContent = validContent.map(c => {
        const preview = c.content.substring(0, CONTENT_PREVIEW_CHARS);
        totalChars += preview.length;
        return totalChars <= MAX_CONTENT_PER_STAGE 
            ? `URL: ${c.url}\n${preview}...` 
            : null;
    }).filter(Boolean);

    const prompt = `
VULNERABILITY RESEARCH SYNTHESIS
Exploit: ${entry.name}
Disclosed: ${entry.extracted_metadata?.disclosure_date || 'unknown'}

SEARCH RESULTS:
${JSON.stringify(searchResults.slice(0, 5), null, 2)}

REASONING:
${reasoning}

EXTRACTED CONTENT (capped at ${MAX_CONTENT_PER_STAGE} chars total):
${truncatedContent.join('\n---\n')}

Output a structured mental model as JSON:
{
  "vulnerability_type": "string",
  "affected_component": "string", 
  "trigger_condition": "string",
  "preconditions": ["string"],
  "impact": "string",
  "technical_indicators": {"port": "number|null", "protocol": "string"},
  "confidence": 0.0-1.0,
  "unknowns": ["string"]
}
`;
    
    const synthesis = await callLLM(prompt, STAGE1_PROMPT);
    
    try {
        const parsed = parseLLMJson(synthesis);
        context.synthesizedOutput = parsed;
        context.confidence = typeof parsed.confidence === 'number' ? parsed.confidence : 0.3;
        return parsed;
    } catch (parseError) {
        console.warn(`  ⚠ JSON parse failed: ${parseError.message}`);
        console.warn(`  Raw response preview: ${synthesis?.substring(0, 200)}...`);
        
        // Fallback: try to extract key fields with regex as last resort
        const fallback = {
            raw: synthesis,
            confidence: 0.3,
            unknowns: [`Parse failed: ${parseError.message}`],
            // Attempt regex extraction for critical fields (optional)
            vulnerability_type: synthesis?.match(/"vulnerability_type"\s*:\s*"([^"]+)"/)?.[1],
            affected_component: synthesis?.match(/"affected_component"\s*:\s*"([^"]+)"/)?.[1],
        };
        
        context.synthesizedOutput = fallback;
        context.confidence = 0.3;
        return fallback;
    }
}

// ===== STAGE 2: UNDERSTAND SOFTWARE =====

const STAGE2_PROMPT = `You are a software archaeologist. Determine:
- Official name, vendor, product lineage
- Version timeline and EOL status
- Architecture: standalone app, service, library, plugin, suite
- Dependencies: OS, frameworks, other software
- Installation patterns and prerequisites

Cite sources. Separate facts from inferences.`;

async function stage2Planner(entry, mentalModel, context) {
    const tasks = [];
    const product = entry.extracted_metadata?.product || entry.product || 'unknown';
    const vendor = entry.extracted_metadata?.vendor || 'unknown';
    const version = entry.extracted_metadata?.tested_version || '';
    
    // Software identification search
    tasks.push(new Task({
        type: 'web_search',
        query: `"${product}" ${vendor} software history version ${version}`,
        priority: 10,
        metadata: { purpose: 'software_id' }
    }));
    
    // Acquisition reconnaissance
    tasks.push(new Task({
        type: 'web_search',
        query: `"${product}" download archive legacy version`,
        priority: 9,
        metadata: { purpose: 'acquisition_recon' }
    }));
    
    // Classification reasoning
    tasks.push(new Task({
        type: 'reasoning',
        query: `Vuln context: ${JSON.stringify(mentalModel)}. What type of software is "${product}"? Standalone, service, library, plugin? What's needed to install/run it?`,
        priority: 8,
        metadata: { systemPrompt: STAGE2_PROMPT }
    }));
    
    // Microsoft products get special handling
    const isMs = (vendor || '').toLowerCase().includes('microsoft') || 
                 (product || '').toLowerCase().includes('windows');
    if (isMs) {
        tasks.push(new Task({
            type: 'reasoning',
            query: `Microsoft product "${product}". For lab setup: enable via Windows Features, optional components, or separate download? Which Windows versions?`,
            priority: 7,
            metadata: { systemPrompt: "You are a Windows platform expert." }
        }));
    }
    
    return tasks;
}

async function stage2Synthesizer(entry, mentalModel, context) {
    const searchResults = Array.from(context.completedTasks.values())
        .filter(t => t.type === 'web_search' && t.result?.success)
        .flatMap(t => t.result.results || []);
    
    const reasoning = Array.from(context.completedTasks.values())
        .filter(t => t.type === 'reasoning')
        .map(t => t.result)
        .join('\n---\n');
    
    const product = entry.extracted_metadata?.product || 'unknown';
    
    const prompt = `
SOFTWARE PROFILE: ${product}

VULN CONTEXT: ${JSON.stringify(mentalModel, null, 2)}
SEARCH: ${JSON.stringify(searchResults.slice(0, 5), null, 2)}
REASONING: ${reasoning}

Output JSON software profile:
{
  "canonical_name": "string",
  "vendor": "string",
  "version_timeline": {"vulnerable": "string", "released": "string|null", "eol": "string|null"},
  "software_type": "standalone_app|windows_service|library|plugin|enterprise_suite|os_component",
  "installation_method": "installer_exe|msi|windows_feature|manual|package_manager",
  "dependencies": ["string"],
  "licensing": "free|freemium|commercial|abandonware|discontinued",
  "acquisition_difficulty": "easy|moderate|hard|impossible",
  "lab_notes": "string",
  "confidence": 0.0-1.0,
  "unknowns": ["string"]
}
`;
    
    const synthesis = await callLLM(prompt, STAGE2_PROMPT);
        
    try {
        const parsed = parseLLMJson(synthesis);
        context.synthesizedOutput = parsed;
        context.confidence = typeof parsed.confidence === 'number' ? parsed.confidence : 0.3;
        return parsed;
    } catch (parseError) {
        console.warn(`  ⚠ JSON parse failed: ${parseError.message}`);
        console.warn(`  Raw response preview: ${synthesis?.substring(0, 200)}...`);
        
        // Fallback: try to extract key fields with regex as last resort
        const fallback = {
            raw: synthesis,
            confidence: 0.3,
            unknowns: [`Parse failed: ${parseError.message}`],
            // Attempt regex extraction for critical fields (optional)
            vulnerability_type: synthesis?.match(/"vulnerability_type"\s*:\s*"([^"]+)"/)?.[1],
            affected_component: synthesis?.match(/"affected_component"\s*:\s*"([^"]+)"/)?.[1],
        };
        
        context.synthesizedOutput = fallback;
        context.confidence = 0.3;
        return fallback;
    }
}

// ===== STAGE 3: CLASSIFY & STRATEGIZE =====

const STAGE3_PROMPT = `Lab provisioning strategist. Classify and plan acquisition:

Classification:
- Deployment: standalone, service, library, plugin, suite
- Acquisition: direct download, archive, vendor request, build, enable OS feature
- Legal: free/test, requires license, abandonware, proprietary
- Effort: trivial, moderate, complex, impractical

Be pragmatic about lab feasibility.`;

async function stage3Planner(entry, mentalModel, softwareProfile, context) {
    const tasks = [];
    const product = entry.extracted_metadata?.product || 'unknown';
    const vendor = entry.extracted_metadata?.vendor || 'unknown';
    const version = entry.extracted_metadata?.tested_version || '';
    const isMs = (vendor || '').toLowerCase().includes('microsoft');
    
    if (isMs) {
        // Microsoft: focus on enablement
        tasks.push(new Task({
            type: 'reasoning',
            query: `Windows component "${product}". PowerShell/DISM commands to enable? Which Windows versions/editions?`,
            priority: 10,
            metadata: { systemPrompt: "You are a Windows deployment expert." }
        }));
        tasks.push(new Task({
            type: 'web_search',
            query: `enable "${product}" Windows feature PowerShell DISM`,
            priority: 9,
            metadata: { purpose: 'ms_enablement' }
        }));
    } else {
        // Third-party: focus on download acquisition
        tasks.push(new Task({
            type: 'web_search',
            query: `"${product}" "${version}" download site:archive.org OR site:oldversion.com`,
            priority: 10,
            metadata: { purpose: 'exact_version' }
        }));
        
        if (vendor && vendor !== 'unknown') {
            tasks.push(new Task({
                type: 'web_search',
                query: `site:${vendor.toLowerCase().replace(/[^a-z0-9.-]/g, '')}.com "${product}" legacy download`,
                priority: 9,
                metadata: { purpose: 'vendor_archive' }
            }));
        }
        
        tasks.push(new Task({
            type: 'archive_lookup',
            query: `"${product}" ${version} installer executable`,
            priority: 8,
            metadata: { purpose: 'archive_recovery' }
        }));
    }
    
    // Low confidence? Spawn open-ended research
    if (context.confidence < 0.5) {
        tasks.push(new Task({
            type: 'open_ended',
            query: `Find ANY source for "${product}" ${version} for security testing lab`,
            priority: 7,
            metadata: { purpose: 'desperate_search' }
        }));
    }
    
    return tasks;
}

async function stage3Synthesizer(entry, mentalModel, softwareProfile, context) {
    const isMs = (entry.extracted_metadata?.vendor || '').toLowerCase().includes('microsoft');
    
    const searchResults = Array.from(context.completedTasks.values())
        .filter(t => t.type === 'web_search' && t.result?.success)
        .flatMap(t => t.result.results || []);
    
    const reasoning = Array.from(context.completedTasks.values())
        .filter(t => t.type === 'reasoning')
        .map(t => t.result)
        .join('\n---\n');
    
    // Extract potential download links
    const downloadLinks = [];
    for (const r of searchResults.slice(0, 5)) {
        if (!r.url || context.isVisited(r.url)) continue;
        const content = await extractPageContent(r.url);
        if (content) {
            context.markVisited(r.url);
            // Heuristic: look for executable file patterns
            const links = content.content?.match(/https?:\/\/[^\s<>"']+?\.(exe|msi|zip|7z)([^\s<>"']*)/gi) || [];
            downloadLinks.push(...links.slice(0, 2));
        }
    }
    
    const prompt = `
ACQUISITION STRATEGY: ${entry.extracted_metadata?.product || 'unknown'}

SOFTWARE PROFILE: ${JSON.stringify(softwareProfile, null, 2)}
SEARCH: ${JSON.stringify(searchResults.slice(0, 5), null, 2)}
REASONING: ${reasoning}
CANDIDATE LINKS: ${downloadLinks.join('\n')}

${isMs ? `
MICROSOFT PRODUCT: Focus on enablement.
What Windows features/commands enable this? Version requirements?
` : `
THIRD-PARTY: Focus on acquisition.
Rank sources by reliability. Flag red flags (malware risk, fake sites).
`}

Output JSON acquisition strategy:
{
  "strategy_type": "enable_windows_feature|direct_download|archive_download|vendor_request|build_source|not_feasible",
  "specific_steps": "string (commands/URLs)",
  "prerequisites": ["string"],
  "risk_assessment": "string",
  "fallback_options": ["string"],
  "estimated_effort": "trivial|moderate|complex|impractical",
  "confidence": 0.0-1.0,
  "unknowns": ["string"]
}
`;
    
    const synthesis = await callLLM(prompt, STAGE3_PROMPT);
    
    try {
        const parsed = parseLLMJson(synthesis);
        context.synthesizedOutput = parsed;
        context.confidence = typeof parsed.confidence === 'number' ? parsed.confidence : 0.3;
        return parsed;
    } catch (parseError) {
        console.warn(`  ⚠ JSON parse failed: ${parseError.message}`);
        console.warn(`  Raw response preview: ${synthesis?.substring(0, 200)}...`);
        
        // Fallback: try to extract key fields with regex as last resort
        const fallback = {
            raw: synthesis,
            confidence: 0.3,
            unknowns: [`Parse failed: ${parseError.message}`],
            // Attempt regex extraction for critical fields (optional)
            vulnerability_type: synthesis?.match(/"vulnerability_type"\s*:\s*"([^"]+)"/)?.[1],
            affected_component: synthesis?.match(/"affected_component"\s*:\s*"([^"]+)"/)?.[1],
        };
        
        context.synthesizedOutput = fallback;
        context.confidence = 0.3;
        return fallback;
    }
}

// ===== STAGE 4: FIND DOWNLOADS (FINAL VERIFICATION) =====

const STAGE4_PROMPT = `Download link verifier. Find and validate actual download URLs.

Prioritize:
- Official vendor archives
- Reputable archives (archive.org, oldversion.com)
- Direct download links (not landing pages)
- File integrity indicators (hashes, signatures)

Flag:
- Suspicious domains, ad-heavy sites, fake buttons
- Version mismatches, wrong platforms
- Broken/redirected links

Conservative: better "not found" than malware link.`;

async function stage4Planner(entry, mentalModel, softwareProfile, acquisitionStrategy, context) {
    const tasks = [];
    const product = entry.extracted_metadata?.product || 'unknown';
    const version = entry.extracted_metadata?.tested_version || '';
    
    // If strategy is Windows feature enablement, verify commands
    if (acquisitionStrategy.acquisition_strategy?.strategy_type === 'enable_windows_feature') {
        const steps = acquisitionStrategy.specific_steps || '';
        tasks.push(new Task({
            type: 'web_search',
            query: `verify "${steps.split('\n')[0] || 'enable windows feature'}" documentation`,
            priority: 10,
            metadata: { purpose: 'command_verification' }
        }));
        tasks.push(new Task({
            type: 'reasoning',
            query: `Validate Windows enablement for "${product}": ${steps}. Correct commands? Version caveats?`,
            priority: 9,
            metadata: { systemPrompt: "You are Windows documentation expert." }
        }));
        return tasks;
    }
    
    // Otherwise: targeted download verification
    const queries = [
        `"${product}" "${version}" filetype:exe OR filetype:msi OR filetype:zip`,
        `site:archive.org "${product}" "${version}" download`,
    ];
    
    // Add vendor-specific if known
    const vendor = entry.extracted_metadata?.vendor;
    if (vendor && vendor !== 'unknown') {
        queries.push(`site:${vendor.toLowerCase().replace(/[^a-z0-9.-]/g, '')}.com "legacy" "${product}"`);
    }
    
    // Verify any specific URLs from strategy
    const strategyText = acquisitionStrategy.specific_steps || '';
    const urlsInStrategy = strategyText.match(/https?:\/\/[^\s]+/g) || [];
    urlsInStrategy.forEach(url => {
        tasks.push(new Task({
            type: 'reasoning',
            query: `Verify download URL: ${url}. Check: domain reputation, file type match, version match, HTTPS.`,
            priority: 10,
            metadata: { systemPrompt: STAGE4_PROMPT }
        }));
    });
    
    // Add targeted searches
    queries.forEach((query, idx) => {
        tasks.push(new Task({
            type: 'web_search',
            query,
            priority: 10 - idx,
            metadata: { purpose: 'final_verification' }
        }));
    });
    
    return tasks;
}

async function stage4Synthesizer(entry, mentalModel, softwareProfile, acquisitionStrategy, context) {
    const searchResults = Array.from(context.completedTasks.values())
        .filter(t => t.type === 'web_search' && t.result?.success)
        .flatMap(t => t.result.results || []);
    
    const reasoning = Array.from(context.completedTasks.values())
        .filter(t => t.type === 'reasoning')
        .map(t => t.result)
        .join('\n---\n');
    
    // Validate candidate URLs with lightweight HEAD requests
    const candidates = [];
    for (const r of searchResults.slice(0, 10)) {
        if (!r.url || context.isVisited(r.url)) continue;
        
        const looksDirect = r.url.match(/\.(exe|msi|zip|7z)($|\?)/i) || 
                           r.title?.toLowerCase().includes('download') ||
                           r.snippet?.toLowerCase().includes('direct');
        
        if (looksDirect) {
            context.markVisited(r.url);
            candidates.push({ url: r.url, title: r.title, snippet: r.snippet });
        }
    }
    
    // Lightweight validation
    const validated = [];
    for (const c of candidates.slice(0, 5)) {
        try {
            const res = await fetch(c.url, { 
                method: 'HEAD', 
                signal: AbortSignal.timeout(5000),
                redirect: 'follow'
            });
            validated.push({
                ...c,
                status: res.status,
                contentType: res.headers.get('content-type'),
                finalUrl: res.url,
                likelyValid: res.ok && (res.headers.get('content-type')?.includes('application/') || res.url.match(/\.(exe|msi|zip)/i))
            });
        } catch {
            validated.push({ ...c, status: 'error', likelyValid: false });
        }
    }
    
    const prompt = `
FINAL DOWNLOAD VERIFICATION: ${entry.extracted_metadata?.product || 'unknown'} v${entry.extracted_metadata?.tested_version || '?'}

STRATEGY: ${JSON.stringify(acquisitionStrategy, null, 2)}
VALIDATED CANDIDATES: ${JSON.stringify(validated, null, 2)}
REASONING: ${reasoning}

${validated.filter(u => u.likelyValid).length > 0 ? `
PROMISING DOWNLOADS. Rank by:
1. Authenticity (official > reputable archive > unknown)
2. Version match confidence  
3. File type correctness
4. Safety (HTTPS, no ad redirects)

Select BEST option or report none safe.
` : `
NO RELIABLE DOWNLOADS FOUND.

Consider:
- Abandonware with no legitimate sources?
- Build from source if available?
- Enable Windows feature instead?
- Mark "not feasible for lab"?
`}

Output JSON final recommendation:
{
  "recommendation": "download_url|enable_feature_command|build_source|not_feasible",
  "value": "string (URL/command)",
  "verification_steps": ["string"],
  "risk_warnings": ["string"],
  "confidence": 0.0-1.0,
  "next_steps": ["string"]
}
`;
    
    const synthesis = await callLLM(prompt, STAGE4_PROMPT);
    
    try {
        const parsed = parseLLMJson(synthesis);
        context.synthesizedOutput = parsed;
        context.confidence = typeof parsed.confidence === 'number' ? parsed.confidence : 0.3;
        return parsed;
    } catch (parseError) {
        console.warn(`  ⚠ JSON parse failed: ${parseError.message}`);
        console.warn(`  Raw response preview: ${synthesis?.substring(0, 200)}...`);
        
        // Fallback: try to extract key fields with regex as last resort
        const fallback = {
            raw: synthesis,
            confidence: 0.3,
            unknowns: [`Parse failed: ${parseError.message}`],
            // Attempt regex extraction for critical fields (optional)
            vulnerability_type: synthesis?.match(/"vulnerability_type"\s*:\s*"([^"]+)"/)?.[1],
            affected_component: synthesis?.match(/"affected_component"\s*:\s*"([^"]+)"/)?.[1],
        };
        
        context.synthesizedOutput = fallback;
        context.confidence = 0.3;
        return fallback;
    }
}

// ===== STAGE EXECUTION LOOP =====

async function runStageLoop(entryContext, stageKey, planner, synthesizer, stageLabel) {
    const context = entryContext.stages[stageKey];
    
    log(`\n${'='.repeat(60)}`);
    log(`🔍 STAGE: ${stageLabel}`);
    log(`Entry: ${entryContext.entryId}`);
    log(`Starting loop: ${context.loopCount + 1}/${MAX_RESEARCH_DEPTH}`);
    log(`Current confidence: ${context.confidence.toFixed(2)} (threshold: ${context.confidenceThreshold})`);
    log(`${'='.repeat(60)}`);
    
    while (!context.canProceed()) {
        context.loopCount++;
        log(`\n🔄 Loop iteration #${context.loopCount}`);
        
        // === GATHER INPUTS FOR PLANNER ===
        const inputs = [entryContext.rawEntry];
        if (stageKey === 'stage2') inputs.push(entryContext.stages.stage1.synthesizedOutput);
        if (stageKey === 'stage3') {
            inputs.push(entryContext.stages.stage1.synthesizedOutput);
            inputs.push(entryContext.stages.stage2.synthesizedOutput);
        }
        if (stageKey === 'stage4') {
            inputs.push(entryContext.stages.stage1.synthesizedOutput);
            inputs.push(entryContext.stages.stage2.synthesizedOutput);
            inputs.push(entryContext.stages.stage3.synthesizedOutput);
        }
        
        if (TEST_MODE.verboseLogging) {
            logJSON(`Planner inputs for ${stageLabel}`, {
                entry_summary: {
                    name: entryContext.rawEntry.name,
                    msf_path: entryContext.rawEntry.msf_path,
                    product: entryContext.rawEntry.extracted_metadata?.product,
                    version: entryContext.rawEntry.extracted_metadata?.tested_version,
                },
                prior_stage_outputs: inputs.slice(1).map((o, i) => ({
                    stage: i + 1,
                    confidence: o?.confidence,
                    keys: o ? Object.keys(o).filter(k => k !== 'raw') : []
                }))
            }, 'info');
        }
        
        // === PLANNER EXECUTION ===
        log(`\n📋 Planner generating tasks...`);
        const plannerInputs = [entryContext.rawEntry, ...inputs.slice(1)];

        if (context.loopCount > 1 && context.synthesizedOutput) {
            plannerInputs.push({
                prior_synthesis: context.synthesizedOutput,
                prior_confidence: context.confidence,
                research_gap: context.synthesizedOutput.unknowns // What we still don't know
            });
        }

        const newTasks = await planner(...plannerInputs, context);      
          
        if (TEST_MODE.verboseLogging) {
            logJSON(`Planner output: ${newTasks.length} tasks generated`, 
                newTasks.map(t => ({
                    id: t.id.slice(0,8),
                    type: t.type,
                    query: t.query?.substring(0, 100),
                    depends_on: t.depends_on,
                    priority: t.priority
                }))
            );
        }
        
        newTasks.forEach(t => context.addTask(t));
        
        // === TASK EXECUTION ===
        let executed = 0;
        const pending = context.getPendingTasks();
        log(`\n⚙️  Executing ${pending.length} pending tasks...`);
        
        for (const task of pending) {
            log(`  → Running: ${task.type} | ${task.query?.substring(0, 80)}...`);
            try {
                const result = await executeTask(task, context);
                context.completedTasks.set(task.id, task);
                executed++;
                
                logTaskExecution(task, result, context);
                
                // Checkpoint + small delay
                await entryContext.saveCheckpoint();
                await new Promise(r => setTimeout(r, 1000));
            } catch (e) {
                console.warn(`    ✗ Task ${task.id.slice(0,8)} failed: ${e.message}`);
                context.errors.push({ taskId: task.id, error: e.message, timestamp: new Date().toISOString() });
            }
        }
        
        // Deadlock protection
        if (executed === 0 && pending.length > 0) {
            log(`\n⚠️  Dependency deadlock detected, forcing synthesis`);
            break;
        }
        
        // === SYNTHESIZER EXECUTION ===
        log(`\n🧠 Synthesizer running...`);
        const synthInputs = [entryContext.rawEntry, ...inputs.slice(1)];
        
        if (TEST_MODE.verboseLogging && context.completedTasks.size > 0) {
            const taskSummary = Array.from(context.completedTasks.values()).map(t => ({
                type: t.type,
                status: t.status,
                result_preview: t.result ? 
                    (typeof t.result === 'string' ? t.result.substring(0, 150) : 
                     JSON.stringify(t.result).substring(0, 150)) : null
            }));
            logJSON(`Synthesizer context: ${taskSummary.length} completed tasks`, taskSummary);
        }
        
        await synthesizer(...synthInputs, context);
        
        log(`\n✅ Synthesis complete`);
        log(`   Confidence: ${context.confidence.toFixed(2)} ${context.confidence >= context.confidenceThreshold ? '✓' : '✗'}`);
        
        if (TEST_MODE.verboseLogging && context.synthesizedOutput) {
            logJSON(`Synthesized output`, context.synthesizedOutput);
        }
        
        // === CONFIDENCE GATE EVALUATION ===
        if (context.confidence >= context.confidenceThreshold) {
            log(`\n🎯 Confidence threshold met! Proceeding to next stage.`);
            break;
        }
        
        if (context.loopCount >= context.maxLoops) {
            log(`\n⚠️  Max loops (${MAX_RESEARCH_DEPTH}) reached. Proceeding with confidence ${context.confidence.toFixed(2)}`);
            break;
        }
        
        log(`\n🔁 Confidence below threshold, looping again...`);
    }
    
    log(`\n${'─'.repeat(60)}`);
    log(`🏁 Stage ${stageLabel} finished`);
    log(`Final confidence: ${context.confidence.toFixed(2)}`);
    log(`Total loops: ${context.loopCount}`);
    log(`URLs visited: ${context.visitedUrls.size}`);
    log(`${'─'.repeat(60)}\n`);
    
    return context.synthesizedOutput;
}

// ===== MAIN ENTRY PROCESSOR =====

async function processEntry(entry) {
    // Filter: only initial_foothold
    if (entry.access_type !== 'initial_foothold') {
        log(`  ⊘ Skipping ${entry.msf_path}: access_type !== 'initial_foothold'`);
        return null;
    }
    
    log(`\n🚀 [${entry.msf_path}] Starting research pipeline`);
    logJSON(`Raw entry (filtered fields)`, {
        name: entry.name,
        msf_path: entry.msf_path,
        access_type: entry.access_type,
        extracted_metadata: entry.extracted_metadata
    });
    
    const entryContext = new EntryContext(entry);
    
    const loadCheckPointBoolean = await entryContext.loadCheckpoint();
    if (!loadCheckPointBoolean) {
        await entryContext.saveCheckpoint();
        log(`  ✓ Created new checkpoint file`);
    }
    
    try {
        // === STAGE 1: Understand vulnerability ===
        if (!entryContext.stages.stage1.synthesizedOutput) {
            await runStageLoop(entryContext, 'stage1', stage1Planner, stage1Synthesizer, 'UNDERSTAND VULNERABILITY');
            await entryContext.saveCheckpoint();
            
            // === EARLY EXIT FOR TESTING ===
            if (TEST_MODE.enabled && TEST_MODE.stopAfterStage === 'stage1') {
                log(`\n🛑 TEST MODE: Stopping after Stage 1 as configured`);
                entryContext.finalResult = {
                    entry: entryContext.rawEntry,
                    stage1_result: entryContext.stages.stage1.synthesizedOutput,
                    stage1_confidence: entryContext.stages.stage1.confidence,
                    stage1_loops: entryContext.stages.stage1.loopCount,
                    test_mode_note: "Pipeline stopped early for validation",
                    completed_at: new Date().toISOString()
                };
                
                // Write Stage 1 only output
                const testOutput = {
                    ...entryContext.finalResult,
                    visited_urls_stage1: Array.from(entryContext.stages.stage1.visitedUrls),
                    errors_stage1: entryContext.stages.stage1.errors
                };
                await appendToAggregatedResults(entryContext.entryId, testOutput);
                log(`\n💾 Appended to aggregated results: ${OUTPUT_FILE}`);
                
                return testOutput;
            }
        }
        
        // === STAGE 2: Understand software ===
        if (!entryContext.stages.stage2.synthesizedOutput) {
            await runStageLoop(entryContext, 'stage2', stage2Planner, stage2Synthesizer, 'UNDERSTAND SOFTWARE');
            await entryContext.saveCheckpoint();
            
            if (TEST_MODE.enabled && TEST_MODE.stopAfterStage === 'stage2') {
                log(`\n🛑 TEST MODE: Stopping after Stage 2`);
                entryContext.finalResult = {
                    entry: entryContext.rawEntry,
                    stage1_result: entryContext.stages.stage1.synthesizedOutput,
                    stage2_result: entryContext.stages.stage2.synthesizedOutput,
                    stage2_confidence: entryContext.stages.stage2.confidence,
                    stage2_loops: entryContext.stages.stage2.loopCount,
                    test_mode_note: "Pipeline stopped after Stage 2 for validation",
                    completed_at: new Date().toISOString()
                };
                
                const testOutput = {
                    ...entryContext.finalResult,
                    visited_urls: Array.from(new Set([
                        ...entryContext.stages.stage1.visitedUrls,
                        ...entryContext.stages.stage2.visitedUrls
                    ])),
                    errors: [...entryContext.stages.stage1.errors, ...entryContext.stages.stage2.errors]
                };
                
                // ✅ Append to aggregated results file (not individual file)
                await appendToAggregatedResults(entryContext.entryId, testOutput);
                log(`\n💾 Appended to aggregated results: ${OUTPUT_FILE}`);
                
                return testOutput;
            }
        }
                
        // === STAGE 3: Classify software ===
        if (!entryContext.stages.stage3.synthesizedOutput) {
            await runStageLoop(entryContext, 'stage3', stage3Planner, stage3Synthesizer, 'CLASSIFY SOFTWARE');
            await entryContext.saveCheckpoint();
            
            if (TEST_MODE.enabled && TEST_MODE.stopAfterStage === 'stage3') {
                log(`\n🛑 TEST MODE: Stopping after Stage 3`);
                entryContext.finalResult = {
                    entry: entryContext.rawEntry,
                    stage1_result: entryContext.stages.stage1.synthesizedOutput,
                    stage2_result: entryContext.stages.stage2.synthesizedOutput,
                    stage3_result: entryContext.stages.stage3.synthesizedOutput,
                    stage3_confidence: entryContext.stages.stage3.confidence,
                    stage3_loops: entryContext.stages.stage3.loopCount,
                    test_mode_note: "Pipeline stopped after Stage 3 for validation",
                    completed_at: new Date().toISOString()
                };
                
                const testOutput = {
                    ...entryContext.finalResult,
                    visited_urls: Array.from(new Set([
                        ...entryContext.stages.stage1.visitedUrls,
                        ...entryContext.stages.stage2.visitedUrls,
                        ...entryContext.stages.stage3.visitedUrls
                    ])),
                    errors: [
                        ...entryContext.stages.stage1.errors,
                        ...entryContext.stages.stage2.errors,
                        ...entryContext.stages.stage3.errors
                    ]
                };
                
                await appendToAggregatedResults(entryContext.entryId, testOutput);
                log(`\n💾 Appended to aggregated results: ${OUTPUT_FILE}`);
                
                return testOutput;
            }
        }

        // === STAGE 4: Find downloads ===
        if (!entryContext.stages.stage4.synthesizedOutput) {
            await runStageLoop(entryContext, 'stage4', stage4Planner, stage4Synthesizer, 'FIND DOWNLOADS');
            await entryContext.saveCheckpoint();
            
            if (TEST_MODE.enabled && TEST_MODE.stopAfterStage === 'stage4') {
                log(`\n🛑 TEST MODE: Stopping after Stage 4`);
                entryContext.finalResult = {
                    entry: entryContext.rawEntry,
                    stage1_result: entryContext.stages.stage1.synthesizedOutput,
                    stage2_result: entryContext.stages.stage2.synthesizedOutput,
                    stage3_result: entryContext.stages.stage3.synthesizedOutput,
                    stage4_result: entryContext.stages.stage4.synthesizedOutput,
                    stage4_confidence: entryContext.stages.stage4.confidence,
                    stage4_loops: entryContext.stages.stage4.loopCount,
                    test_mode_note: "Pipeline stopped after Stage 4 for validation",
                    completed_at: new Date().toISOString()
                };
                
                const testOutput = {
                    ...entryContext.finalResult,
                    visited_urls: Array.from(new Set([
                        ...entryContext.stages.stage1.visitedUrls,
                        ...entryContext.stages.stage2.visitedUrls,
                        ...entryContext.stages.stage3.visitedUrls,
                        ...entryContext.stages.stage4.visitedUrls
                    ])),
                    errors: [
                        ...entryContext.stages.stage1.errors,
                        ...entryContext.stages.stage2.errors,
                        ...entryContext.stages.stage3.errors,
                        ...entryContext.stages.stage4.errors
                    ]
                };
                
                await appendToAggregatedResults(entryContext.entryId, testOutput);
                log(`\n💾 Appended to aggregated results: ${OUTPUT_FILE}`);
                
                return testOutput;
            }
        }
        
        // === FULL PIPELINE COMPLETE ===
        entryContext.finalResult = {
            entry: entryContext.rawEntry,
            stages: {
                vulnerability_model: entryContext.stages.stage1.synthesizedOutput,
                software_profile: entryContext.stages.stage2.synthesizedOutput,
                acquisition_strategy: entryContext.stages.stage3.synthesizedOutput,
                final_recommendation: entryContext.stages.stage4.synthesizedOutput
            },
            overall_confidence: Math.min(
                entryContext.stages.stage1.confidence,
                entryContext.stages.stage2.confidence,
                entryContext.stages.stage3.confidence,
                entryContext.stages.stage4.confidence
            ),
            completed_at: new Date().toISOString()
        };
        
        const finalOutput = {
            ...entryContext.finalResult,
            visited_urls: Array.from(new Set(
                Object.values(entryContext.stages).flatMap(s => Array.from(s.visitedUrls))
            )),
            errors: Object.values(entryContext.stages).flatMap(s => s.errors)
        };

        // ✅ Append to aggregated results file (not individual file)
        await appendToAggregatedResults(entryContext.entryId, finalOutput);
        log(`\n✅ Pipeline complete → appended to ${OUTPUT_FILE}`);

        return finalOutput;
        
    } catch (error) {
        console.error(`  ✗ Failed: ${error.message}`);
        await entryContext.saveCheckpoint();
        throw error;
    }
}

// ===== BATCH PROCESSOR =====

async function main() {
    await $`mkdir -p ${OUTPUT_DIR}/checkpoints`; 
    await $`mkdir -p ./output`; 

    const inputData = await Bun.file(INPUT_FILE).json();
    const entries = Array.isArray(inputData) ? inputData : Object.values(inputData);
    
    let targets = entries.filter(e => e.access_type === 'initial_foothold');

    // === TESTING: Process only first matching entry ===
    if (TEST_MODE.enabled) {
        const testEntry = targets.find(e => e.msf_path?.includes('winvnc_http_get'));
        if (testEntry) {
            targets = [testEntry];
            log(`\n🧪 TEST MODE: Processing single entry: ${testEntry.msf_path}`);
        }
    }

    console.log(`Processing ${targets.length} initial_foothold entries`);
    
    const results = [];
    
    for (const entry of targets) {
        try {
            const result = await processEntry(entry);
            if (result) results.push(result);
        } catch (error) {
            console.error(`Skipping ${entry.msf_path}: ${error.message}`);
            // Continue with next entry
        }
    }  
    console.log(`\n✓ Batch complete: ${OUTPUT_FILE}`);
}

// Run if executed directly
if (import.meta.main) {
    main().catch(console.error);
}

