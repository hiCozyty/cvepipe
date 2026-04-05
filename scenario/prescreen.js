#!/usr/bin/env bun

/**
 * Exploit Prescreen: Windows Replicability Assessment Agent
 * Single-stage research: "Can this exploit be replicated on Windows Server 2016-2022 or Windows 10/11?"
 * 
 * Architecture: Planner → Executor → Synthesizer (per task)
 * Uses same constants + infrastructure as original 4-stage version
 */

import { $ } from 'bun';
import { JSDOM, VirtualConsole } from 'jsdom';
import { Readability } from '@mozilla/readability';
import { OpenAI } from 'openai';
import Bottleneck from 'bottleneck';

const crypto = globalThis.crypto;

// ============================================================================
// Configuration (Preserved from Original)
// ============================================================================

const SEARXNG_ENDPOINT = process.env.SEARXNG_ENDPOINT;
const SEARXNG_TIMEOUT = parseInt(process.env.SEARXNG_TIMEOUT || '10000', 10);
const MAX_RESEARCH_DEPTH = 5;
const RESULTS_PER_SEARCH = 10;

const OUTPUT_DIR = './data/prescreen';
const CACHE_RESULTS = true;
const DEBUG_LLM = true;

const LLM_API_KEY = process.env.LLM_API_KEY;
const LLM_BASE_URL = process.env.LLM_BASE_URL;
const LLM_MODEL = process.env.LLM_MODEL;
const LLM_TEMPERATURE = 0;
const LLM_MAX_TOKENS = 16384;

const EXTRACT_TOP_N = 10;
const EXTRACT_CONTENT_TOP_N = 7;
const CONTENT_PREVIEW_CHARS = 15000;
const MIN_ARTICLE_LENGTH = 200;
const MAX_CONTENT_PER_STAGE = 80000;

const INPUT_FILE = './output/filtered_modules.json';
const OUTPUT_FILE = './output/prescreen_results.json';

const TEST_MODE = {
    enabled: false,
    stopAfterStage: null,
    verboseLogging: true,
    prettyPrint: true,
};

// ============================================================================
// Logging & Utilities
// ============================================================================

function log(...args) { console.log(...args); }

function parseLLMJson(response) {
    if (!response) throw new Error('Empty response');
    let cleaned = response.replace(/^```(?:json)?\s*|\s*```$/g, '').trim();
    
    const startBrace = cleaned.indexOf('{');
    const endBrace = cleaned.lastIndexOf('}');
    const startBracket = cleaned.indexOf('[');
    const endBracket = cleaned.lastIndexOf(']');
    
    let startIdx = Math.max(startBrace, startBracket);
    let endIdx = Math.max(endBrace, endBracket);
    
    if (startBrace !== -1 && endBrace !== -1 && endBrace > startBrace) {
        startIdx = startBrace; endIdx = endBrace;
    } else if (startBracket !== -1 && endBracket !== -1 && endBracket > startBracket) {
        startIdx = startBracket; endIdx = endBracket;
    } else {
        throw new Error(`No valid JSON bounds found: ${response.substring(0, 100)}...`);
    }
    
    const jsonStr = cleaned.substring(startIdx, endIdx + 1).trim();
    return JSON.parse(jsonStr);
}

async function appendToAggregatedResults(entryId, result, outputFile = OUTPUT_FILE) {
    const fileRef = Bun.file(outputFile);
    let aggregated = { processed: 0, timestamp: new Date().toISOString(), results: {} };
    
    if (await fileRef.exists()) {
        try {
            aggregated = await fileRef.json();
            if (Array.isArray(aggregated.results)) {
                const migrated = {};
                for (const r of aggregated.results) {
                    const key = r.entry?.msf_path || r.entryId || crypto.randomUUID();
                    migrated[key] = r;
                }
                aggregated.results = migrated;
            }
            if (typeof aggregated.results !== 'object' || aggregated.results === null || Array.isArray(aggregated.results)) {
                aggregated.results = {};
            }
        } catch (e) {
            console.warn(`⚠ Failed to read existing results: ${e.message}. Starting fresh.`);
            aggregated.results = {};
        }
    }
    
    const key = entryId;
    if (aggregated.results[key]) {
        log(`  ↻ Updating entry: ${key}`);
        aggregated.results[key] = { ...aggregated.results[key], ...result, updated_at: new Date().toISOString() };
    } else {
        log(`  ➕ Adding entry: ${key}`);
        aggregated.results[key] = { ...result, added_at: new Date().toISOString() };
    }
    
    aggregated.processed = Object.keys(aggregated.results).length;
    aggregated.last_updated = new Date().toISOString();
    
    const tempFile = `${outputFile}.tmp.${Date.now()}`;
    await Bun.write(tempFile, JSON.stringify(aggregated, null, 2));
    await $`mv ${tempFile} ${outputFile}`;
    
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

// ============================================================================
// Pre-Filtering: Reduce 1000+ → ~200 High-Value Exploits
// ============================================================================

function preFilterExploits(entries) {
    return entries.filter(entry => {
        // Must be initial_foothold
        if (entry.access_type !== 'initial_foothold') return false;
 
        const meta = entry.extracted_metadata || {};
        
        const yearStr = meta.disclosure_date?.split('-')[0];
        const year = yearStr ? parseInt(yearStr, 10) : null;
        
        if (!year || year <= 2016) {
            // console.log(`  ⊘ Excluding ${entry.msf_path}: disclosed ${year || 'unknown'} (<= 2016)`);
            return false;
        }
        
        return true;
    });
}


function filterRelevantResults(results, entry) {
    // No filtering - return all results as-is
    return results?.filter(r => r?.url) || [];
}

// ============================================================================
// Rate Limiting & Infrastructure
// ============================================================================

const searxngLimiter = new Bottleneck({ minTime: 10_000, maxConcurrent: 1 });
const llmLimiter = new Bottleneck({ minTime: 10_000, maxConcurrent: 1 });
let lastRequestTime = 0;

async function rateLimitedDelay() {
    const now = Date.now();
    const elapsed = now - lastRequestTime;
    if (elapsed < 10000) {
        await new Promise(resolve => setTimeout(resolve, 10000 - elapsed));
    }
    lastRequestTime = Date.now();
}

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
            log(`  [LLM] ${content.substring(0, 200)}...`);
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
        const filtered = results.results?.filter?.(r => r?.url && !context.isVisited(r.url)) || [];
        filtered.forEach(r => context.markVisited(r.url));
        log('url: ',url)
        log(`  🔍 Search "${query}": ${results.results?.length || 0} raw results → ${filtered.length} after visited filter`);

        return {
            success: true,
            query,
            results: filtered.slice(0, EXTRACT_TOP_N),
            totalFound: results.number_of_results,
            timestamp: new Date().toISOString()
        };
    } catch (error) {
        return { success: false, query, error: error.message, timestamp: new Date().toISOString() };
    }
}

async function extractPageContent(url) {
    try {
        const response = await fetch(url, { 
            signal: AbortSignal.timeout(15000),
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

// ============================================================================
// Core Data Structures (Simplified for Single Stage)
// ============================================================================

class Task {
    constructor({ type, query, depends_on = [], metadata = {}, priority = 0 }) {
        this.id = crypto.randomUUID();
        this.type = type; // 'web_search' | 'reasoning' | 'archive_lookup' | 'open_ended'
        this.query = query;
        this.depends_on = depends_on;
        this.metadata = metadata;
        this.priority = priority;
        this.status = 'pending';
        this.result = null;
        this.error = null;
        this.attempts = 0;
    }
}

class AssessmentContext {
    constructor(entryId) {
        this.entryId = entryId;
        this.tasks = new Map();
        this.completedTasks = new Map();
        this.visitedUrls = new Set();
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
        return this.confidence >= this.confidenceThreshold || this.loopCount >= this.maxLoops;
    }
    
    getPendingTasks() {
        return Array.from(this.tasks.values())
            .filter(t => t.status === 'pending')
            .filter(t => t.depends_on.every(depId => {
                const dep = this.completedTasks.get(depId);
                return dep && dep.status === 'completed';
            }))
            .sort((a, b) => b.priority - a.priority);
    }
}

class EntryContext {
    constructor(entry) {
        this.entryId = entry.msf_path || `entry_${crypto.randomUUID().slice(0,8)}`;
        this.rawEntry = entry;
        this.assessment = new AssessmentContext(this.entryId);
        this.finalResult = null;
        this.checkpointFile = `${OUTPUT_DIR}/checkpoints/${this.entryId.replace(/\//g, '_')}.checkpoint.json`;
    }
    
    async saveCheckpoint() {
        const checkpoint = {
            entryId: this.entryId,
            rawEntry: this.rawEntry,
            assessment: {
                synthesizedOutput: this.assessment.synthesizedOutput,
                confidence: this.assessment.confidence,
                loopCount: this.assessment.loopCount,
                visitedUrls: Array.from(this.assessment.visitedUrls),
                errors: this.assessment.errors
            },
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
            this.finalResult = checkpoint.finalResult;
            const a = this.assessment;
            a.synthesizedOutput = checkpoint.assessment?.synthesizedOutput;
            a.confidence = checkpoint.assessment?.confidence || 0;
            a.loopCount = checkpoint.assessment?.loopCount || 0;
            a.visitedUrls = new Set(checkpoint.assessment?.visitedUrls || []);
            a.errors = checkpoint.assessment?.errors || [];
            log(`  ↻ Resumed from checkpoint`);
            return true;
        } catch (e) {
            console.error(`  ✗ Failed to load checkpoint: ${e.message}`);
            return false;
        }
    }
}

// ============================================================================
// Task Execution: Planner → Executor → Synthesizer Pattern
// ============================================================================

async function executeTask(task, context, entry) {  // ← Added entry param
    task.status = 'running';
    task.attempts++;
    
    try {
        switch (task.type) {
            case 'web_search':
                task.result = await executeWebSearch(task.query, context);
                if (task.result.success && task.result.results) {
                    task.result.results = filterRelevantResults(task.result.results, entry);
                }
                break;
                
            case 'reasoning':
                task.result = await callLLM(task.query, task.metadata.systemPrompt);
                break;
                
            case 'archive_lookup':
                const archiveQuery = `${product} ${version} download archive`.replace(/\s+/g, ' ').trim();

                task.result = await executeWebSearch(archiveQuery, context);
                if (task.result.success && task.result.results) {
                    task.result.results = filterRelevantResults(task.result.results, entry); 
                }
                break;
                
            case 'open_ended':
                const subQueries = await callLLM(
                    `Research goal: "${task.query}". Generate 3-5 specific, targeted search queries about Windows compatibility and download availability. Return one per line.`,
                    "You are a research query optimizer for DuckDuckGo."
                );
                
                const queries = subQueries.split('\n').map(q => q.trim()).filter(q => q && q.length > 10);
                const results = await Promise.all(queries.map(q => executeWebSearch(q, context)));
                
                task.result = {
                    type: 'open_ended',
                    goal: task.query,
                    subQueries: queries,
                    results: results.filter(r => r?.success).map(r => ({
                        ...r,
                        results: filterRelevantResults(r.results || [], entry)
                    }))
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
        context.errors.push({ taskId: task.id, type: task.type, error: error.message, timestamp: new Date().toISOString() });
        throw error;
    }
}

// ============================================================================
// THE ASSESSMENT PROMPT (Single Question Focus)
// ============================================================================

const ASSESSMENT_SYSTEM_PROMPT = `You are a Windows security lab architect specializing in exploit reproducibility.

YOUR GOAL: Determine if the TARGET SOFTWARE/FEATURE for a Metasploit exploit can be OBTAINED and SET UP in a vulnerability research lab.

IMPORTANT CONTEXT:
- The user maintains a lab with VARIOUS Windows builds (including old, unpatched, vulnerable versions).
- Do NOT evaluate whether the exploit works on "modern" or "patched" systems.
- ONLY evaluate: Can the target be acquired and installed on a Windows version that the exploit supports?

CRITICAL RULES:
1. If target is a Windows built-in feature (IIS, SMB, RDP, WinRM, etc.) → confirm it exists in ANY Windows version the exploit targets (even if disabled by default or removed in later builds).
2. If software is legacy/abandonware but available via archive.org, oldversion.com, GitHub releases, etc. → acquisition_path = "download_from_archive" (this is VALID).
3. If setup requires email verification, phone call, paid license with no trial, or physical media → automation_feasibility = "cannot_automate".
4. If the target requires an OS outside the user's lab scope (e.g., Windows 95, non-Windows) → note in version_compatibility.
5. If version compatibility is uncertain but plausible via VM, compatibility mode, or side-by-side install → do NOT reject; note caveats.
6. Confidence <0.5 → recommended_next_action = "manual_review_required".
7. Be conservative about malware/untrusted download links, but NOT about legitimate archive sources.
8. Output STRICT JSON matching the schema below. No markdown, no explanations outside JSON.`;


const ASSESSMENT_USER_TEMPLATE = `
EXPLOIT DATA:
{{ENTRY_JSON}}

RESEARCH CONTEXT:
- Search results: {{SEARCH_RESULTS}}
- Extracted content previews (capped): {{CONTENT_PREVIEWS}}
- Prior reasoning notes: {{REASONING_NOTES}}

OUTPUT STRICT JSON WITH THIS SCHEMA:
{
  "setup_feasible": boolean,
  "target_type": "built_in_windows_feature" | "third_party_software" | "legacy_abandonware" | "not_applicable",
  "acquisition_path": "enable_via_powershell" | "download_from_archive" | "vendor_request" | "build_from_source" | "not_feasible",
  "specific_instructions": "string (concrete commands, URLs, or steps to obtain and install the target)",
  "version_requirements": {
    "exploit_targets": ["Windows versions from exploit metadata"],
    "lab_compatible": ["Windows versions in user's lab that can run the target"],
    "known_incompatible": ["versions where target definitively cannot run"],
    "notes": "string (e.g., 'requires Windows 7 SP1', '32-bit only', 'needs .NET 2.0')"
  },
  "automation_feasibility": "fully_automated" | "requires_manual_steps" | "cannot_automate",
  "blocking_factors": ["email_verification", "paid_license", "physical_media", "discontinued_no_archive", "32bit_only_on_64bit_os", "non_windows_os", "none"],
  "risk_warnings": ["security warnings about running vulnerable code or legacy software"],
  "confidence": 0.0-1.0,
  "recommended_next_action": "proceed_to_lab" | "exclude_from_batch" | "manual_review_required"
}

DECISION GUIDANCE:
✅ setup_feasible = true IF:
   - Target is a Windows built-in feature that exists in ANY Windows version the exploit targets, OR
   - Third-party/legacy software has a legitimate download source (archive.org, GitHub, oldversion.com, vendor archive, etc.) AND can run on a Windows version the user can provide

❌ setup_feasible = false ONLY IF:
   - Target requires a non-Windows OS, OR
   - Software has NO legitimate download source AND cannot be built from source, OR
   - Setup requires irreversible manual barriers (phone verification, paid license with no trial, physical media only)

🔑 KEY PRINCIPLE:
   - This assessment is about ENVIRONMENT SETUP FEASIBILITY for vulnerability research.
   - Assume the user can provide old, unpatched, or vulnerable Windows builds.
   - Do NOT reject because "this is patched in latest updates" or "this is legacy".

📊 CONFIDENCE SCORING:
   - 0.8-1.0: Direct evidence (working download link, exact PowerShell command, archive URL with checksum)
   - 0.5-0.7: Indirect but plausible evidence (forum post confirming availability, archive mention without direct link)
   - <0.5: Speculative or no evidence → recommend manual review

🎯 RECOMMENDED_NEXT_ACTION:
   - "proceed_to_lab": confidence ≥0.7 AND automation_feasibility ≠ "cannot_automate"
   - "manual_review_required": confidence <0.5 OR ambiguous blocking factors
   - "exclude_from_batch": acquisition_path = "not_feasible" AND no plausible workaround
`;

// ============================================================================
// PLANNER: Generate Targeted Research Tasks
// ============================================================================

async function assessmentPlanner(entry, context) {
    const tasks = [];
    const meta = entry.extracted_metadata || {};
    const product = meta.product || entry.name || 'unknown';
    const vendor = meta.vendor || 'unknown';
    const version = meta.tested_version || '';
    const cve = entry.cves?.[0] || '';
    
    // Priority 10: Direct Windows compatibility queries (simplified)
    tasks.push(new Task({
        type: 'web_search',
        query: `${product} ${version} Windows compatibility`.replace(/\s+/g, ' ').trim(),
        priority: 10,
        metadata: { purpose: 'windows_compatibility' }
    }));

    // Priority 9: Download/archive availability (simplified)
    tasks.push(new Task({
        type: 'web_search',
        query: `${product} ${version} download`.replace(/\s+/g, ' ').trim(),
        priority: 9,
        metadata: { purpose: 'download_availability' }
    }));

    // Priority 8: CVE research (keep as-is, usually works)
    if (cve) {
        tasks.push(new Task({
            type: 'web_search',
            query: `CVE-${cve} ${product} exploit`, 
            priority: 8,
            metadata: { purpose: 'cve_research' }
        }));
    }
    
    // Priority 7: Windows built-in feature verification (if applicable)
    const isWindowsBuiltin = ['microsoft', 'windows', 'iis', 'smb', 'rdp', 'winrm', 'rpc', 'lsass', 'spooler', 'http.sys']
        .some(kw => (vendor + product).toLowerCase().includes(kw));
    
    if (isWindowsBuiltin) {
        tasks.push(new Task({
            type: 'reasoning',
            query: `Is "${product}" a built-in Windows feature? If yes, what PowerShell/DISM command enables it on Windows 10/11/Server 2016+? Are there version caveats?`,
            priority: 7,
            metadata: { systemPrompt: "You are a Windows platform expert." }
        }));
    } else {
        // Priority 7: Archive lookup for third-party legacy software
        tasks.push(new Task({
            type: 'archive_lookup',
            query: `"${product}" ${version} installer executable download`,
            priority: 7,
            metadata: { purpose: 'legacy_archive' }
        }));
    }
    
    // Priority 6: Open-ended research if confidence is low or product is obscure
    if (!version || version === 'unknown' || product.toLowerCase().includes('unknown')) {
        tasks.push(new Task({
            type: 'open_ended',
            query: `Find authoritative sources about "${product}" software: version history, download sources, Windows compatibility`,
            priority: 6,
            metadata: { purpose: 'obscure_product_research' }
        }));
    }
    
    return tasks;
}

// ============================================================================
// SYNTHESIZER: Generate Final Assessment JSON
// ============================================================================

async function assessmentSynthesizer(entry, context) {
    // Gather completed task results
    const searchResults = Array.from(context.completedTasks.values())
        .filter(t => t.type === 'web_search' && t.result?.success)
        .flatMap(t => t.result.results || []);
    
    const reasoning = Array.from(context.completedTasks.values())
        .filter(t => t.type === 'reasoning')
        .map(t => t.result)
        .join('\n---\n');
    
    const trustedFirst = [...searchResults]
    
    const contentPreviews = [];
    let totalChars = 0;
    
    for (const r of trustedFirst.slice(0, EXTRACT_CONTENT_TOP_N)) {
        if (!r.url || context.isVisited(r.url)) continue;
        const content = await extractPageContent(r.url);
        if (content?.content?.length >= MIN_ARTICLE_LENGTH && totalChars < MAX_CONTENT_PER_STAGE) {
            const preview = content.content.substring(0, CONTENT_PREVIEW_CHARS);
            contentPreviews.push(`URL: ${content.url}\nTitle: ${content.title}\n${preview}...`);
            totalChars += preview.length;
            context.markVisited(r.url);
        }
    }
    
    // Build prompt with template substitution
    let prompt = ASSESSMENT_USER_TEMPLATE
        .replace('{{ENTRY_JSON}}', JSON.stringify(entry, null, 2))
        .replace('{{SEARCH_RESULTS}}', JSON.stringify(searchResults.slice(0, 7), null, 2))
        .replace('{{CONTENT_PREVIEWS}}', contentPreviews.join('\n---\n'))
        .replace('{{REASONING_NOTES}}', reasoning || 'None');
    
    const synthesis = await callLLM(prompt, ASSESSMENT_SYSTEM_PROMPT);
    
    try {
        const parsed = parseLLMJson(synthesis);
        context.synthesizedOutput = parsed;
        context.confidence = typeof parsed.confidence === 'number' ? parsed.confidence : 0.3;
        return parsed;
    } catch (parseError) {
        console.warn(`  ⚠ JSON parse failed: ${parseError.message}`);
        console.warn(`  Raw response preview: ${synthesis?.substring(0, 300)}...`);
        
        // Fallback: minimal structured output
        const fallback = {
            setup_feasible: false, 
            target_type: "not_applicable",
            acquisition_path: "not_feasible",
            specific_instructions: "",
            version_requirements: {  // ← Also updated from version_compatibility
                exploit_targets: [],
                lab_compatible: [],
                known_incompatible: [],
                notes: "Parse error"
            },
            automation_feasibility: "cannot_automate",
            blocking_factors: ["parse_error"],
            risk_warnings: [parseError.message],
            confidence: 0.2,
            recommended_next_action: "manual_review_required",
            raw_response_preview: synthesis?.substring(0, 500)
        };
                
        context.synthesizedOutput = fallback;
        context.confidence = 0.2;
        return fallback;
    }
}

// ============================================================================
// MAIN ASSESSMENT LOOP (Single Stage, Planner→Executor→Synthesizer)
// ============================================================================

async function runAssessmentLoop(entryContext) {
    const ctx = entryContext.assessment;
    const entry = entryContext.rawEntry;
    
    log(`\n${'='.repeat(70)}`);
    log(`🎯 WINDOWS REPLICABILITY ASSESSMENT`);
    log(`Entry: ${entryContext.entryId}`);
    log(`Question: "Can the target software/feature be obtained and set up for vulnerability testing?"`);
    log(`Starting loop: ${ctx.loopCount + 1}/${MAX_RESEARCH_DEPTH}`);
    log(`${'='.repeat(70)}`);
    
    while (!ctx.canProceed()) {
        ctx.loopCount++;
        log(`\n🔄 Assessment iteration #${ctx.loopCount}`);
        
        // === PLANNER PHASE ===
        log(`\n📋 Planner: Generating research tasks...`);
        const newTasks = await assessmentPlanner(entry, ctx);
        
        if (TEST_MODE.verboseLogging) {
            logJSON(`Planner output: ${newTasks.length} tasks`, 
                newTasks.map(t => ({ id: t.id.slice(0,8), type: t.type, query: t.query?.substring(0, 100), priority: t.priority }))
            );
        }
        
        newTasks.forEach(t => ctx.addTask(t));
        
        // === EXECUTOR PHASE ===
        let executed = 0;
        const pending = ctx.getPendingTasks();
        log(`\n⚙️  Executor: Running ${pending.length} pending tasks...`);
        
        for (const task of pending) {
            log(`  → ${task.type}: ${task.query?.substring(0, 80)}${task.query?.length > 80 ? '...' : ''}`);
            try {
                const result = await executeTask(task, ctx, entry);
                ctx.completedTasks.set(task.id, task);
                executed++;
                
                if (task.result?.success && task.result.results?.length) {
                    log(`    ✓ Found ${task.result.results.length} relevant results`);
                    task.result.results.slice(0, 2).forEach(r => {
                        log(`      • ${r.title?.substring(0, 60)}... → ${r.url}`);
                    });
                }
                
                await entryContext.saveCheckpoint();
                await new Promise(r => setTimeout(r, 500)); // Small delay between tasks
            } catch (e) {
                console.warn(`    ✗ Task ${task.id.slice(0,8)} failed: ${e.message}`);
            }
        }
        
        // Deadlock protection
        if (executed === 0 && pending.length > 0) {
            log(`\n⚠️  Dependency deadlock detected, proceeding to synthesis`);
            break;
        }
        
        // === SYNTHESIZER PHASE ===
        log(`\n🧠 Synthesizer: Generating final assessment...`);
        await assessmentSynthesizer(entry, ctx);
        
        log(`\n✅ Assessment complete`);
        log(`   Confidence: ${ctx.confidence.toFixed(2)} ${ctx.confidence >= ctx.confidenceThreshold ? '✓' : '✗'}`);
        log(`   Recommendation: ${ctx.synthesizedOutput?.recommended_next_action || 'unknown'}`);
        
        if (TEST_MODE.verboseLogging && ctx.synthesizedOutput) {
            logJSON(`Synthesized assessment`, ctx.synthesizedOutput);
        }
        
        // === CONFIDENCE GATE ===
        if (ctx.confidence >= ctx.confidenceThreshold) {
            log(`\n🎯 Confidence threshold met!`);
            break;
        }
        
        if (ctx.loopCount >= ctx.maxLoops) {
            log(`\n⚠️  Max loops (${MAX_RESEARCH_DEPTH}) reached`);
            break;
        }
        
        log(`\n🔁 Confidence below threshold, looping again...`);
    }
    
    log(`\n${'─'.repeat(70)}`);
    log(`🏁 Assessment finished`);
    log(`Final confidence: ${ctx.confidence.toFixed(2)}`);
    log(`Total loops: ${ctx.loopCount}`);
    log(`URLs visited: ${ctx.visitedUrls.size}`);
    log(`${'─'.repeat(70)}\n`);
    
    return ctx.synthesizedOutput;
}

// ============================================================================
// ENTRY PROCESSOR
// ============================================================================

async function processEntry(entry) {
    log(`\n🚀 [${entry.msf_path}] Starting replicability assessment`);
    
    const entryContext = new EntryContext(entry);
    
    // Checkpoint handling
    const resumed = await entryContext.loadCheckpoint();
    if (!resumed) {
        await entryContext.saveCheckpoint();
        log(`  ✓ Created new checkpoint`);
    }
    
    // Skip if already completed
    if (entryContext.assessment.synthesizedOutput?.recommended_next_action) {
        log(`  ↻ Already assessed: ${entryContext.assessment.synthesizedOutput.recommended_next_action}`);
        return entryContext;
    }
    
    try {
        // Run single-stage assessment loop
        await runAssessmentLoop(entryContext);
        
        // Build final result
        entryContext.finalResult = {
            entry: entryContext.rawEntry,
            assessment: entryContext.assessment.synthesizedOutput,
            confidence: entryContext.assessment.confidence,
            loops: entryContext.assessment.loopCount,
            visited_urls: Array.from(entryContext.assessment.visitedUrls),
            errors: entryContext.assessment.errors,
            completed_at: new Date().toISOString()
        };
        
        // Save and append to aggregated results
        await entryContext.saveCheckpoint();
        await appendToAggregatedResults(entryContext.entryId, entryContext.finalResult);
        
        log(`\n✅ Assessment complete → ${entryContext.finalResult.assessment?.recommended_next_action}`);
        return entryContext;
        
    } catch (error) {
        console.error(`  ✗ Failed: ${error.message}`);
        await entryContext.saveCheckpoint();
        throw error;
    }
}

// ============================================================================
// BATCH PROCESSOR
// ============================================================================

async function main() {
    await $`mkdir -p ${OUTPUT_DIR}/checkpoints`;
    await $`mkdir -p ./output`;
    
    log(`📦 Loading entries from ${INPUT_FILE}...`);
    const inputData = await Bun.file(INPUT_FILE).json();
    const entries = Array.isArray(inputData) ? inputData : Object.values(inputData);
    
    // Apply pre-filtering to reduce volume
    const filtered = preFilterExploits(entries);
    log(`🔍 Pre-filtered: ${entries.length} → ${filtered.length} automatable candidates`);
    
    let targets = filtered;
    
    // Test mode: single entry
    if (TEST_MODE.enabled) {
        const testEntry = targets.find(e => e.msf_path?.includes('winvnc') || e.msf_path?.includes('sip'));
        if (testEntry) {
            targets = [testEntry];
            log(`\n🧪 TEST MODE: Processing ${testEntry.msf_path}`);
        }
    }
    
    if (targets.length === 0) {
        log(`⚠️  No entries match filtering criteria. Check preFilterExploits() logic.`);
        return;
    }
    
    log(`\n🎯 Processing ${targets.length} entries\n`);
    
    const results = [];
    for (const entry of targets) {
        try {
            const ctx = await processEntry(entry);
            if (ctx?.finalResult) results.push(ctx.finalResult);
            
            // Summary stats every 10 entries
            if (results.length % 10 === 0) {
                const actions = results.map(r => r.assessment?.recommended_next_action).filter(Boolean);
                const counts = actions.reduce((acc, a) => ({ ...acc, [a]: (acc[a] || 0) + 1 }), {});
                log(`\n📊 Progress: ${results.length}/${targets.length} | ${JSON.stringify(counts)}`);
            }
        } catch (error) {
            console.error(`Skipping ${entry.msf_path}: ${error.message}`);
        }
    }
    
    // Final triage summary
    const triage = {
        proceed_to_lab: results.filter(r => r.assessment?.recommended_next_action === 'proceed_to_lab').length,
        manual_review: results.filter(r => r.assessment?.recommended_next_action === 'manual_review_required').length,
        exclude: results.filter(r => r.assessment?.recommended_next_action === 'exclude_from_batch').length,
        avg_confidence: results.reduce((sum, r) => sum + (r.confidence || 0), 0) / (results.length || 1)
    };
    
    log(`\n${'═'.repeat(70)}`);
    log(`📋 BATCH COMPLETE: ${OUTPUT_FILE}`);
    log(`   Proceed to lab:    ${triage.proceed_to_lab}`);
    log(`   Manual review:     ${triage.manual_review}`);
    log(`   Exclude:           ${triage.exclude}`);
    log(`   Avg confidence:    ${triage.avg_confidence.toFixed(2)}`);
    log(`${'═'.repeat(70)}\n`);
}

// Run if executed directly
if (import.meta.main) {
    main().catch(console.error);
}