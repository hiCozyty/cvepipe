#!/usr/bin/env bun

/**
 * Exploit Prescreen Stage 2: Download Link & Activation Command Finder
 * 
 * Input: ./output/prescreen_results.json (from previous stage)
 * Output: ./output/download_links.json
 * 
 * For each exploit marked setup_feasible=true:
 * - If third_party/legacy: Find direct download links to vulnerable version
 * - If built_in_windows_feature: Find PowerShell/DISM commands to enable/configure
 */

import { $ } from 'bun';
import { JSDOM, VirtualConsole } from 'jsdom';
import { Readability } from '@mozilla/readability';
import { OpenAI } from 'openai';
import Bottleneck from 'bottleneck';

const crypto = globalThis.crypto;

// ============================================================================
// Configuration
// ============================================================================

const SEARXNG_ENDPOINT = process.env.SEARXNG_ENDPOINT;
const SEARXNG_TIMEOUT = parseInt(process.env.SEARXNG_TIMEOUT || '15000', 10);
const RESULTS_PER_SEARCH = 10;

const INPUT_FILE = './output/prescreen_results.json';
const OUTPUT_FILE = './output/download_links.json';

const LLM_API_KEY = process.env.LLM_API_KEY;
const LLM_BASE_URL = process.env.LLM_BASE_URL;
const LLM_MODEL = process.env.LLM_MODEL;
const LLM_TEMPERATURE = 0;
const LLM_MAX_TOKENS = 8192;

const DEBUG = true;
const TEST_MODE = {
    enabled: false,
    maxEntries: 5,
    verboseLogging: true,
};

// ============================================================================
// Logging & Utilities
// ============================================================================

function log(...args) { if (DEBUG) console.log(...args); }

function parseLLMJson(response, expectedType = 'any') {
    if (!response || typeof response !== 'string') {
        throw new Error(`Empty or invalid response: ${typeof response}`);
    }
    
    let cleaned = response.trim();
    
    // Remove markdown code fences
    cleaned = cleaned.replace(/```(?:json)?\s*/g, '').replace(/\s*```/g, '');
    
    // Try parsing the whole cleaned response first (simplest case)
    try {
        return JSON.parse(cleaned);
    } catch {}
    
    // Find JSON boundaries using BRACE COUNTING (handles nested objects)
    function findCompleteJson(str, startChar, endChar) {
        const startIndex = str.indexOf(startChar);
        if (startIndex === -1) return null;
        
        let depth = 0;
        let inString = false;
        let escaped = false;
        
        for (let i = startIndex; i < str.length; i++) {
            const char = str[i];
            
            if (escaped) {
                escaped = false;
                continue;
            }
            if (char === '\\') {
                escaped = true;
                continue;
            }
            if (char === '"' && !escaped) {
                inString = !inString;
                continue;
            }
            if (inString) continue;
            
            if (char === startChar) depth++;
            if (char === endChar) depth--;
            
            if (depth === 0) {
                return str.substring(startIndex, i + 1);
            }
        }
        return null; // Unclosed JSON
    }
    
    // Extract JSON object or array using brace counting
    let jsonStr = null;
    if (expectedType === 'object' || expectedType === 'any') {
        jsonStr = findCompleteJson(cleaned, '{', '}');
    }
    if (!jsonStr && (expectedType === 'array' || expectedType === 'any')) {
        jsonStr = findCompleteJson(cleaned, '[', ']');
    }
    
    if (!jsonStr) {
        throw new Error(`No complete JSON found. Response: "${response.substring(0, 300)}..."`);
    }
    
    // Minimal cleanup - avoid breaking escaped characters
    jsonStr = jsonStr
        .replace(/,\s*}/g, '}')   // Trailing commas in objects
        .replace(/,\s*]/g, ']');  // Trailing commas in arrays
    // NOTE: Do NOT replace '/' or '\' or newlines - breaks escaping!
    
    try {
        return JSON.parse(jsonStr);
    } catch (parseError) {
        // Last resort: try to fix unescaped backslashes in Windows paths
        // This is a heuristic and may not catch all cases
        const fixedStr = jsonStr.replace(
            /(?<=["'])([^"\\]*)(\\[A-Z]:\\[^"\\]*)(?=["'])/g,
            (match) => match.replace(/\\(?!\\)/g, '\\\\')
        );
        
        try {
            return JSON.parse(fixedStr);
        } catch {
            if (DEBUG) {
                log(`  ✗ JSON parse error: ${parseError.message}`);
                log(`  📄 Extracted snippet (${jsonStr.length} chars):`);
                log(jsonStr.substring(0, 400) + (jsonStr.length > 400 ? '...[truncated]' : ''));
                log(`  📄 Raw response preview (${response.length} chars):`);
                log(response.substring(0, 600) + (response.length > 600 ? '...[truncated]' : ''));
            }
            throw new Error(`JSON parse failed: ${parseError.message}. Snippet: "${jsonStr.substring(0, 150)}..."`);
        }
    }
}
async function appendToResults(entryId, result, outputFile = OUTPUT_FILE) {
    const fileRef = Bun.file(outputFile);
    let aggregated = { processed: 0, timestamp: new Date().toISOString(), results: {} };
    
    if (await fileRef.exists()) {
        try { aggregated = await fileRef.json(); } 
        catch { aggregated.results = {}; }
    }
    
    aggregated.results[entryId] = { ...result, updated_at: new Date().toISOString() };
    aggregated.processed = Object.keys(aggregated.results).length;
    
    const tempFile = `${outputFile}.tmp.${Date.now()}`;
    await Bun.write(tempFile, JSON.stringify(aggregated, null, 2));
    await $`mv ${tempFile} ${outputFile}`;
    
    return aggregated;
}

// ============================================================================
// Rate Limiting
// ============================================================================

const searxngLimiter = new Bottleneck({ minTime: 5000, maxConcurrent: 1 });
const llmLimiter = new Bottleneck({ minTime: 3000, maxConcurrent: 1 });
let lastRequestTime = 0;

async function rateLimitedDelay(ms = 5000) {
    const elapsed = Date.now() - lastRequestTime;
    if (elapsed < ms) await new Promise(r => setTimeout(r, ms - elapsed));
    lastRequestTime = Date.now();
}

async function callLLM(prompt, systemPrompt = "You are a security research assistant.") {
    await rateLimitedDelay(3000);
    const client = new OpenAI({ apiKey: LLM_API_KEY, baseURL: LLM_BASE_URL });
    
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
    
    return response.choices[0].message.content;
}

async function executeWebSearch(query) {
    await rateLimitedDelay(5000);
    
    try {
        const formData = new URLSearchParams();
        formData.append('q', query);
        formData.append('format', 'json');
        formData.append('results', RESULTS_PER_SEARCH.toString());
        
        const response = await searxngLimiter.schedule(() =>
            fetch(`${SEARXNG_ENDPOINT}/search`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: formData,
                signal: AbortSignal.timeout(SEARXNG_TIMEOUT)
            })
        );
        
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        
        log(`  🔍 "${query}": ${data.results?.length || 0} results`);
        return { success: true, query, results: data.results || [] };
    } catch (error) {
        log(`  ✗ Search failed: ${error.message}`);
        return { success: false, query, error: error.message, results: [] };
    }
}

async function extractPageContent(url) {
    try {
        const response = await fetch(url, {
            signal: AbortSignal.timeout(15000),
            headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' }
        });
        if (!response.ok) return null;
        
        const html = await response.text();
        const dom = new JSDOM(html, { virtualConsole: new VirtualConsole() });
        const article = new Readability(dom.window.document).parse();
        
        if (!article || article.textContent?.length < 200) return null;
        
        return {
            url,
            title: article.title,
            content: article.textContent,
            links: Array.from(dom.window.document.querySelectorAll('a[href]'))
                .map(a => ({ text: a.textContent?.trim(), href: a.href }))
                .filter(l => l.href?.startsWith('http'))
        };
    } catch { return null; }
}

// ============================================================================
// Link Validation Helpers
// ============================================================================

const DOWNLOAD_EXTENSIONS = ['.exe', '.msi', '.zip', '.rar', '.7z', '.tar.gz', '.dmg', '.bin', '.sh'];
const DOWNLOAD_KEYWORDS = ['download', 'installer', 'setup', 'archive', 'release', 'binary', 'package'];

function isLikelyDownloadLink(url, text = '') {
    if (!url) return false;
    const lower = (url + ' ' + (text || '')).toLowerCase();
    
    // Direct file extensions
    if (DOWNLOAD_EXTENSIONS.some(ext => lower.endsWith(ext) || lower.includes(ext + '?') || lower.includes(ext + '&'))) {
        return true;
    }
    
    // Download keywords (but exclude info pages)
    if (DOWNLOAD_KEYWORDS.some(kw => lower.includes(kw))) {
        if (['/blog/', '/news/', '/article', '/wiki', '/help', '/support', '/forum', '/question'].some(p => lower.includes(p))) {
            return false;
        }
        return true;
    }
    
    // Known archive/download domains
    const downloadDomains = [
        'archive.org', 'oldversion.com', 'filehippo.com', 'sourceforge.net',
        'github.com', 'gitlab.com', 'bitbucket.org', 'microsoft.com/download',
        'download.microsoft.com', 'ftp.', 'files.', 'cdn.', '/download/', '/releases/'
    ];
    if (downloadDomains.some(d => lower.includes(d))) {
        return true;
    }
    
    return false;
}

function extractDirectDownloadLinks(content, baseUrl) {
    if (!content?.links) return [];
    
    return content.links
        .filter(l => isLikelyDownloadLink(l.href, l.text))
        .map(l => ({
            url: l.href,
            filename: l.href.split('/').pop()?.split('?')[0] || null,
            text: l.text?.substring(0, 100),
            confidence: l.href.match(/\.(exe|msi|zip|rar|7z|tar\.gz)/i) ? 'high' : 'medium',
            extracted_by: 'heuristic'
        }))
        .slice(0, 5);
}

// ============================================================================
// Search Query Generators
// ============================================================================

function generateDownloadQuery(entry) {
    const meta = entry.entry?.extracted_metadata || {};
    const product = meta.product || entry.entry?.name || 'unknown';
    const version = meta.tested_version || '';
    
    const baseQuery = version && version !== 'unknown' 
        ? `"${product}" "${version}" download`
        : `"${product}" download`;
    
    const archiveTerms = ['archive.org', 'oldversion.com', 'legacy', 'historical', 'vulnerable'];
    return `${baseQuery} ${archiveTerms.join(' ')}`.replace(/\s+/g, ' ').trim();
}

function generateActivationQuery(entry) {
    const meta = entry.entry?.extracted_metadata || {};
    const product = meta.product || entry.entry?.name || 'unknown';
    
    return `"${product}" enable PowerShell command OR DISM OR "optional feature" Windows`.replace(/\s+/g, ' ').trim();
}

// ============================================================================
// LLM Prompts - STRICT JSON OUTPUT ENFORCED
// ============================================================================

const LINK_EXTRACTOR_PROMPT = `You are a security researcher extracting download links from web content.

GOAL: From the provided webpage content, extract DIRECT DOWNLOAD LINKS for the target software.

CRITICAL OUTPUT RULES:
1. Return ONLY a JSON array. NO explanations, NO markdown, NO text before or after the JSON.
2. If you cannot find any valid download links, return exactly: []
3. Each link object must have these exact fields:
   - "url": string (the full download URL)
   - "filename": string or null (inferred filename from URL)
   - "version_match": boolean (true if link appears to match target version)
   - "source_domain": string (e.g., "archive.org", "github.com")
   - "confidence": "high" | "medium" | "low"
4. Exclude: blog posts, news articles, documentation, support pages, login pages, forums
5. Prefer: archive.org, oldversion.com, GitHub releases, vendor download pages, FTP servers
6. If uncertain about a link, set confidence to "low" rather than excluding it.

Target product: {{TARGET_PRODUCT}}
Target version: {{TARGET_VERSION}}

CONTENT TO ANALYZE:
{{PAGE_CONTENT}}

OUTPUT (JSON ARRAY ONLY, NO OTHER TEXT):
`;

const COMMAND_EXTRACTOR_PROMPT = `You are a Windows system administrator extracting activation commands.

GOAL: From the provided documentation, extract EXACT PowerShell or DISM commands to enable/configure the target Windows feature.

CRITICAL OUTPUT RULES:
1. Return ONLY a JSON object matching the schema below. NO explanations, NO markdown, NO text before or after.
2. If you cannot find any executable commands, return exactly: {"commands": [], "error": "No commands found"}
3. Commands must be copy-paste executable. For registry paths, use proper PowerShell escaping:
   - Use backticks for special chars: \`$ , \`" , \`'
   - OR use single-quoted strings for literal paths: 'HKLM:\SYSTEM\CurrentControlSet'
4. Include shell type and admin requirement for each command
5. Be specific about version caveats if mentioned in the content.

Required JSON schema:
{
  "commands": [
    {
      "command": "Exact command string to copy-paste",
      "shell": "powershell" | "cmd" | "dism" | "sc",
      "requires_admin": true | false,
      "notes": "Optional context or caveats"
    }
  ],
  "prerequisites": ["Step 1", "Step 2"],
  "version_caveats": "Notes about Windows version compatibility"
}

CONTENT TO ANALYZE:
{{PAGE_CONTENT}}

OUTPUT (JSON OBJECT ONLY, NO OTHER TEXT):
`;

// ============================================================================
// Core Processing Functions
// ============================================================================

async function findDownloadLinks(entry) {
    const assessment = entry.assessment;
    
    if (!assessment?.setup_feasible || assessment.recommended_next_action !== 'proceed_to_lab') {
        return { status: 'skipped', reason: 'not_proceeding' };
    }
    
    const meta = entry.entry?.extracted_metadata || {};
    const product = meta.product || entry.entry?.name || 'unknown';
    const version = meta.tested_version || '';
    
    log(`\n🔗 Finding links for: ${product} ${version}`);
    
    if (assessment.target_type === 'built_in_windows_feature') {
        return await findActivationCommands(entry, assessment);
    } else {
        return await findSoftwareDownloads(entry, assessment);
    }
}

async function findSoftwareDownloads(entry, assessment) {
    const meta = entry.entry?.extracted_metadata || {};
    const product = meta.product || entry.entry?.name || 'unknown';
    const version = meta.tested_version || '';
    
    const queries = [
        generateDownloadQuery(entry),
        `"${product}" "${version}" "download" site:archive.org`,
        `"${product}" installer executable download`
    ].filter(q => q && q.length > 10);
    
    let allLinks = [];
    let visitedUrls = new Set();
    
    for (const query of queries.slice(0, 3)) {
        const searchResult = await executeWebSearch(query);
        if (!searchResult.success) continue;
        
        for (const result of searchResult.results.slice(0, 5)) {
            if (!result.url || visitedUrls.has(result.url)) continue;
            visitedUrls.add(result.url);
            
            const content = await extractPageContent(result.url);
            if (!content) continue;
            
            // Try heuristic extraction first (fast, reliable)
            const directLinks = extractDirectDownloadLinks(content, result.url);
            if (directLinks.length > 0) {
                allLinks.push(...directLinks);
                log(`  ✓ Found ${directLinks.length} download links on ${result.url}`);
                break;
            }
            
            // Fallback to LLM if content is substantial
            if (content.content?.length > 500) {
                try {
                    const prompt = LINK_EXTRACTOR_PROMPT
                        .replace('{{TARGET_PRODUCT}}', product)
                        .replace('{{TARGET_VERSION}}', version || 'latest')
                        .replace('{{PAGE_CONTENT}}', content.content.substring(0, 12000));
                    
                    const llmResponse = await callLLM(prompt, "You extract download links from web content. Output JSON array only.");
                    const extracted = parseLLMJson(llmResponse, 'array');
                    
                    if (Array.isArray(extracted) && extracted.length > 0) {
                        allLinks.push(...extracted.map(l => ({ ...l, extracted_by_llm: true })));
                        log(`  ✓ LLM extracted ${extracted.length} links from ${result.url}`);
                        break;
                    }
                } catch (e) {
                    log(`  ⚠ LLM parse failed: ${e.message}`);
                    // Fallback to heuristics even if LLM failed
                    const fallbackLinks = extractDirectDownloadLinks(content, result.url);
                    if (fallbackLinks.length > 0) {
                        log(`  ✓ Fallback: extracted ${fallbackLinks.length} links via heuristics`);
                        allLinks.push(...fallbackLinks);
                        break;
                    }
                }
            }
        }
        
        if (allLinks.length >= 3) break;
    }
    
    // Deduplicate and rank
    const uniqueLinks = Array.from(new Map(
        allLinks.map(l => [l.url, l])
    ).values()).sort((a, b) => {
        const confOrder = { high: 3, medium: 2, low: 1 };
        if (confOrder[b.confidence] !== confOrder[a.confidence]) {
            return confOrder[b.confidence] - confOrder[a.confidence];
        }
        return (b.version_match ? 1 : 0) - (a.version_match ? 1 : 0);
    }).slice(0, 5);
    
    return {
        status: uniqueLinks.length > 0 ? 'success' : 'no_links_found',
        target_type: 'third_party_software',
        product,
        version,
        download_links: uniqueLinks,
        search_queries_used: queries.slice(0, 3),
        urls_analyzed: Array.from(visitedUrls).slice(0, 10)
    };
}

async function findActivationCommands(entry, assessment) {
    const meta = entry.entry?.extracted_metadata || {};
    const product = meta.product || entry.entry?.name || 'unknown';
    
    log(`  ⚙️  Finding activation commands for: ${product}`);
    
    const queries = [
        generateActivationQuery(entry),
        `"${product}" PowerShell enable feature`,
        `DISM enable "${product}" Windows`
    ].filter(q => q && q.length > 10);
    
    let bestCommands = null;
    
    for (const query of queries.slice(0, 3)) {
        const searchResult = await executeWebSearch(query);
        if (!searchResult.success) continue;
        
        for (const result of searchResult.results.slice(0, 3)) {
            if (!result.url) continue;
            
            const content = await extractPageContent(result.url);
            if (!content?.content) continue;
            
            try {
                const prompt = COMMAND_EXTRACTOR_PROMPT
                    .replace('{{PAGE_CONTENT}}', content.content.substring(0, 12000));
                
                const llmResponse = await callLLM(prompt, "You extract Windows activation commands. Output JSON object only.");
                const extracted = parseLLMJson(llmResponse, 'object');
                
                if (extracted?.commands?.length > 0) {
                    bestCommands = {
                        ...extracted,
                        source_url: result.url,
                        source_title: result.title
                    };
                    log(`  ✓ Extracted ${extracted.commands.length} commands from ${result.url}`);
                    break;
                }
            } catch (e) {
                log(`  ⚠ Command extraction failed: ${e.message}`);
            }
        }
        
        if (bestCommands) break;
    }
    
    // Fallback to assessment instructions
    if (!bestCommands && assessment.specific_instructions) {
        log(`  ⚠ Using fallback instructions from assessment`);
        bestCommands = {
            commands: [{
                command: assessment.specific_instructions,
                shell: 'powershell',
                requires_admin: true,
                notes: 'From prescreen assessment - may need verification'
            }],
            prerequisites: [],
            version_caveats: assessment.version_requirements?.notes || '',
            fallback: true
        };
    }
    
    return {
        status: bestCommands?.commands?.length > 0 ? 'success' : 'no_commands_found',
        target_type: 'built_in_windows_feature',
        product,
        activation_commands: bestCommands,
        search_queries_used: queries.slice(0, 3)
    };
}

// ============================================================================
// Main Processing Loop
// ============================================================================

async function main() {
    log(`🚀 Starting download link finder`);
    log(`📥 Input: ${INPUT_FILE}`);
    log(`📤 Output: ${OUTPUT_FILE}`);
    
    const prescreenData = await Bun.file(INPUT_FILE).json();
    const entries = Object.values(prescreenData.results || {});
    
    const targets = entries.filter(e => 
        e.assessment?.setup_feasible === true && 
        e.assessment?.recommended_next_action === 'proceed_to_lab'
    );
    
    log(`📊 Found ${targets.length}/${entries.length} entries to process`);
    
    if (targets.length === 0) {
        log(`⚠️  No entries match criteria. Check prescreen output.`);
        return;
    }
    
    const processList = TEST_MODE.enabled 
        ? targets.slice(0, TEST_MODE.maxEntries) 
        : targets;
    
    if (TEST_MODE.enabled) {
        log(`🧪 TEST MODE: Processing ${processList.length} entries`);
    }
    
    const results = [];
    for (const entry of processList) {
        const entryId = entry.entry?.msf_path || entry.entryId || crypto.randomUUID().slice(0, 12);
        
        try {
            log(`\n🔍 Processing: ${entryId}`);
            const result = await findDownloadLinks(entry);
            
            await appendToResults(entryId, {
                entry: entry.entry,
                assessment_summary: {
                    setup_feasible: entry.assessment?.setup_feasible,
                    target_type: entry.assessment?.target_type,
                    acquisition_path: entry.assessment?.acquisition_path,
                    recommended_next_action: entry.assessment?.recommended_next_action
                },
                ...result
            });
            
            results.push({ entryId, status: result.status });
            
            if (results.length % 5 === 0) {
                const counts = results.reduce((acc, r) => {
                    acc[r.status] = (acc[r.status] || 0) + 1;
                    return acc;
                }, {});
                log(`\n📈 Progress: ${results.length}/${processList.length} | ${JSON.stringify(counts)}`);
            }
            
        } catch (error) {
            log(`  ✗ Error processing ${entryId}: ${error.message}`);
            await appendToResults(entryId, {
                entry: entry.entry,
                status: 'error',
                error: error.message,
                stack: DEBUG ? error.stack : undefined
            });
        }
    }
    
    const summary = results.reduce((acc, r) => {
        acc[r.status] = (acc[r.status] || 0) + 1;
        return acc;
    }, {});
    
    log(`\n${'═'.repeat(60)}`);
    log(`✅ BATCH COMPLETE: ${OUTPUT_FILE}`);
    log(`   Processed: ${results.length}`);
    log(`   Results: ${JSON.stringify(summary)}`);
    
    const byType = results.map(r => {
        const entry = prescreenData.results[r.entryId];
        return entry?.assessment?.target_type;
    }).filter(Boolean).reduce((acc, t) => {
        acc[t] = (acc[t] || 0) + 1;
        return acc;
    }, {});
    
    log(`   By target type: ${JSON.stringify(byType)}`);
    log(`${'═'.repeat(60)}\n`);
}

if (import.meta.main) {
    main().catch(console.error);
}