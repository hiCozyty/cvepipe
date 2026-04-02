#!/usr/bin/env bun

/**
 * Exploit Prescreen: VM Reproducibility Research Agent
 * Filters exploits and performs agentic deep research via SearXNG + LLM
 * 
 * FOCUS: Find download links for vulnerable software versions only.
 * Control/patched version research removed due to edge-case complexity.
 */

import { $ } from 'bun';
import { JSDOM, VirtualConsole } from 'jsdom';
import { Readability } from '@mozilla/readability';
import { OpenAI } from 'openai';
import Bottleneck from 'bottleneck';

// ============================================================================
// Configuration
// ============================================================================

const SEARXNG_ENDPOINT = process.env.SEARXNG_ENDPOINT;
const SEARXNG_TIMEOUT = parseInt(process.env.SEARXNG_TIMEOUT || '3000', 10);
const MAX_RESEARCH_DEPTH = 10;
const RESULTS_PER_SEARCH = 10;
const EXTRACT_TOP_N = 5;
const MIN_ARTICLE_LENGTH = 300;
const OUTPUT_DIR = './data/prescreen';
const CACHE_RESULTS = true;

const LLM_API_KEY =  process.env.LLM_API_KEY;
const LLM_BASE_URL = process.env.LLM_BASE_URL;
const LLM_MODEL = process.env.LLM_MODEL;
const LLM_TEMPERATURE = 0.1;
const LLM_MAX_TOKENS = 16384;

const INPUT_FILE = './output/test.json';
const OUTPUT_FILE = './output/prescreen_results.json';

// Rate limiting: 1 request per 10s to avoid throttling
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

// ============================================================================
// Simple LLM Client
// ============================================================================
function parseLLMJson(response) {
    try {
        // Remove markdown code fences if present
        const cleaned = response.replace(/```json?\n?/g, '').replace(/```\s*$/g, '').trim();
        return JSON.parse(cleaned);
    } catch (e) {
        console.warn(`[JSON_PARSE] First attempt failed: ${e.message}`);
        
        // Try 2: Remove trailing commas (common LLM mistake)
        try {
            const noTrailingComma = response.replace(/,\s*([\]}])/g, '$1');
            const cleaned = noTrailingComma.replace(/```json?\n?/g, '').replace(/```\s*$/g, '').trim();
            return JSON.parse(cleaned);
        } catch (e2) {
            console.warn(`[JSON_PARSE] Second attempt failed: ${e2.message}`);
            return null;
        }
    }
}
function createLLMClient() {
    if (!LLM_API_KEY) throw new Error('LLM_API_KEY or NVIDIA_NIM_API_KEY environment variable is not set');
    return new OpenAI({
        apiKey: LLM_API_KEY,
        baseURL: LLM_BASE_URL
    });
}

async function callLLM(messages, { temperature = LLM_TEMPERATURE, max_tokens = LLM_MAX_TOKENS, model = LLM_MODEL } = {}) {
    return llmLimiter.schedule(async () => {
        await rateLimitedDelay();
        const client = createLLMClient();
        const response = await client.chat.completions.create({
            model,
            messages,
            temperature,
            top_p: 0.1,
            max_tokens,
            stream: false
        });
        return response.choices[0].message.content;
    });
}

// ============================================================================
// SearXNG Helper
// ============================================================================

function sanitizeSnippet(text) {
    if (!text) return "";
    return text
        .replace(/<[^>]*>/gm, '')
        .replace(/\s+/g, ' ')
        .trim();
}

async function searchSearXNG(query, config = {}) {
    const endpoint = config.endpoint || SEARXNG_ENDPOINT;
    const timeout = config.timeout || SEARXNG_TIMEOUT;
    
    try {
        const url = `${endpoint}/search?q=${encodeURIComponent(query)}&format=json`;
        const response = await fetch(url, { signal: AbortSignal.timeout(timeout) });
        const data = await response.json();
        
        return (data.results || [])
            .filter(r => r.content && r.content.length > 20)  // Relaxed for blog/forum recall
            .slice(0, RESULTS_PER_SEARCH)
            .map(r => ({
                title: sanitizeSnippet(r.title),
                url: r.url,
                content: sanitizeSnippet(r.content)
            }));
    } catch (error) {
        console.error(`[SEARCH] Error querying "${query}": ${error.message}`);
        return [];
    }
}

// ============================================================================
// Article Text Extraction
// ============================================================================

async function extractArticleText(url) {
    if (!url) return "";
    
    try {
        const response = await fetch(url, {
            headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0' }
        });
        const html = await response.text();
        
        const virtualConsole = new VirtualConsole();
        virtualConsole.on("error", () => { /* Skip parsing noise */ });
        
        const dom = new JSDOM(html, { url, virtualConsole });
        const reader = new Readability(dom.window.document);
        const article = reader.parse();
        
        if (!article || !article.textContent) return "";
        
        return article.textContent
            .replace(/\n\s*\n/g, '\n')
            .replace(/[ \t]+/g, ' ')
            .trim();
    } catch (error) {
        console.warn(`[EXTRACT] Could not scrape ${url}: ${error.message}`);
        return "";
    }
}

// ============================================================================
// Source Credibility Scoring
// ============================================================================

function scoreDownloadSource(url) {
    const tiers = {
        'high': ['vendor.com', 'github.com', 'archive.org', 'rapid7.com', 'microsoft.com', 'exploit-db.com'],
        'medium': ['sourceforge.net', 'fossies.org', 'softpedia.com', 'filehippo.com', 'softonic.com'],
        'low': ['unknown', 'blog', 'forum']
    };
    
    const urlLower = url.toLowerCase();
    for (const [score, domains] of Object.entries(tiers)) {
        if (domains.some(d => urlLower.includes(d))) return score;
    }
    return 'unverified';
}

// ============================================================================
// URL Validation Helper
// ============================================================================

function validateDownloadUrl(url, version) {
    const warnings = [];
    
    // Flag dynamic redirectors that may require browser/cookies
    if (/redirect|dyn-|download\.php|click\.php|postdq\.php/i.test(url)) {
        warnings.push("URL is a redirector; may require browser/cookies");
    }
    
    return warnings;
}

// ============================================================================
// Main Prescreen Entry Point
// ============================================================================

export async function prescreenExploits(exploits, options = {}) {
    const results = [];
    const config = {
        searxngEndpoint: options.searxngEndpoint || SEARXNG_ENDPOINT,
        searxngTimeout: options.searxngTimeout || SEARXNG_TIMEOUT
    };
    
    // Filter: only replicable initial_foothold exploits
    const candidates = exploits.filter(e => 
        e.replicable === true && e.access_type === 'initial_foothold'
    );
    
    console.log(`🎯 Prescreening ${candidates.length}/${exploits.length} exploits for VM reproducibility...`);
    
    for (const exploit of candidates) {
        try {
            console.log(`🔍 Researching: ${exploit.name}`);
            const research = await analyzeExploitReproducibility(exploit, config);
            results.push(research);
            
            if (CACHE_RESULTS) {
                await $`mkdir -p ${OUTPUT_DIR}`;
                await Bun.write(
                    `${OUTPUT_DIR}/${exploit.msf_path.replace(/\//g, '_')}.json`,
                    JSON.stringify(research, null, 2)
                );
            }
        } catch (error) {
            console.error(`❌ Failed to research ${exploit.name}: ${error.message}`);
            results.push({
                exploitName: exploit.name,
                msfPath: exploit.msf_path,
                status: 'error',
                error: error.message,
                timestamp: new Date().toISOString()
            });
        }
    }
    
    return results;
}

// ============================================================================
// Agentic Research Loop (Per Exploit) - SINGLE PHASE: Vulnerable Version Only
// ============================================================================

async function analyzeExploitReproducibility(exploit, config, maxDepth = MAX_RESEARCH_DEPTH) {
    const context = {
        exploit: {
            name: exploit.name,
            description: exploit.description,
            msf_path: exploit.msf_path,
            provisioning_complexity: exploit.provisioning_complexity,
            disclosed: exploit.disclosed
        },
        knowledgeBase: [],
        searchedQueries: new Set(),
        analyzedUrls: new Set()
    };
    
    // Research vulnerable version downloads (≤ disclosure date)
    const disclosureDate = exploit.disclosed || "unknown";
    console.log(`  🎯 Finding vulnerable version downloads (≤ ${disclosureDate})`);
    
    let depth = 0;
    let isComplete = false;
    
    while (!isComplete && depth < maxDepth) {
        const queryPlan = await generateVulnerableQueries(context, depth);
        
        if (queryPlan.isComplete) {
            isComplete = true;
            break;
        }
        
        for (const query of queryPlan.queries) {
            if (context.searchedQueries.has(query)) continue;
            context.searchedQueries.add(query);
            
            try {
                const rawResults = await searchSearXNG(query, config);
                if (!rawResults.length) continue;
                
                const enrichedResults = await Promise.all(
                    rawResults.slice(0, EXTRACT_TOP_N).map(async (res) => {
                        try {
                            const fullText = await extractArticleText(res.url);
                            return { ...res, fullText: fullText?.length > MIN_ARTICLE_LENGTH ? fullText : null };
                        } catch {
                            return { ...res, fullText: null };
                        }
                    })
                );
                
                const validResults = enrichedResults.filter(r => r.fullText);
                const newResults = validResults.filter(r => {
                    if (context.analyzedUrls.has(r.url)) return false;
                    context.analyzedUrls.add(r.url);
                    return true;
                });
                if (!newResults.length) continue;  // Nothing new to analyze

                const distilled = await distillVulnerableLinks(validResults, exploit, query, disclosureDate);
                if (distilled?.downloadUrls?.length > 0) {
                    context.knowledgeBase.push({
                        query,
                        sources: validResults.map(r => ({ url: r.url, title: r.title })),
                        findings: distilled
                    });
                }
            } catch (err) {
                console.warn(`[QUERY] Failed "${query}": ${err.message}`);
            }
        }
        depth++;
        console.log(`🔄 Iteration ${depth}/${maxDepth} complete for ${exploit.name}`);
    }
    
    // Aggregate results and synthesize final report
    const vulnerableSoftware = aggregateVulnerableResults(context.knowledgeBase, exploit, disclosureDate);
    return synthesizeFinalReport(exploit, vulnerableSoftware);
}

// ============================================================================
// Query Generation: Find Vulnerable Version Downloads
// ============================================================================

async function generateVulnerableQueries(context, iteration) {
    // FIX: Correct destructuring - knowledgeBase is at context level, not context.exploit
    const exploit = context.exploit;
    const knowledgeBase = context.knowledgeBase;
    const disclosed = exploit.disclosed;
    
    const previousFindings = knowledgeBase.map(k => 
        `• ${k.query}: found ${k.findings?.downloadUrls?.length || 0} links`
    ).join('\n');
    
    const prompt = `You are researching DOWNLOAD LINKS for the VULNERABLE version of this software.

EXPLOIT: ${exploit}
MODULE: ${exploit.msf_path}
DISCLOSURE DATE: ${disclosed}

GOAL: Find at least 3 download links for the vulnerable version (released ON OR BEFORE ${disclosed}).

PREVIOUS RESULTS:
${previousFindings || 'None yet.'}

SEARCH STRATEGY:
- Focus on sources from 6 months BEFORE to disclosure date: ${disclosed}
- Search vendor archives, archive.org, blogs, forums, mirrors, exploit-db, softpedia, oldversion.com
- Use date-range queries: "software download 2022", "setup.exe september 2022"
- Look for versioned filenames: "SoftwareName_3.6.0.4.exe"

QUERY GUIDELINES:
- Be specific: "SoftwareName 3.6.0.4 download site:archive.org 2022"
- Max 8 words per query
- Target: archive.org, vendor archives, mirrors, blogs, forums, software directories

Respond with VALID JSON ONLY:
{
  "isComplete": boolean,
  "reasoning": "1 sentence on progress",
  "queries": ["query1", "query2"]
}`;

    try {
        const response = await callLLM([
            { role: 'system', content: 'Output valid JSON only. No markdown.' },
            { role: 'user', content: prompt }
        ], { temperature: 0.1 });
        
        const parsed = parseLLMJson(response);

        if (!parsed || !Array.isArray(parsed.queries)) {
            console.warn(`[QUERY_GEN] Invalid response structure`);
            return { isComplete: iteration >= 4, reasoning: 'Fallback', queries: [] };
        }

        return {
            isComplete: parsed.isComplete === true,
            reasoning: parsed.reasoning || '',
            queries: Array.isArray(parsed.queries) ? parsed.queries.slice(0, 3) : []
        };
    } catch (e) {
        console.warn(`[QUERY_GEN] Failed: ${e.message}`);
        return { isComplete: iteration >= 4, reasoning: 'Fallback', queries: [] };
    }
}

// ============================================================================
// Intel Distillation: Extract Download Links
// ============================================================================

async function distillVulnerableLinks(results, exploit, query, disclosureDate) {
    const contentBlocks = results.map((r, i) => 
        `SOURCE ${i+1} [${r.url}]:\n${(r.fullText || '').slice(0, 16000)}\n---`
    ).join('\n\n');

    const prompt = `Extract DOWNLOAD LINKS for the VULNERABLE version of this software.

EXPLOIT: ${exploit}
DISCLOSURE DATE: ${disclosureDate}
SEARCH QUERY: "${query}"

CONTENT:
${contentBlocks}

EXTRACT:
✅ Find AT LEAST 3 download URLs for the vulnerable version (≤ ${disclosureDate})
✅ For each URL, infer version from filename or page text
✅ Note if URL is direct download or redirector
✅ Prioritize links with timestamps near or before ${disclosureDate}

IGNORE:
- Generic blog posts without download links
- Patched version discussions (we only want vulnerable version downloads)

Respond with VALID JSON:
{
  "downloadUrls": ["https://link1", "https://link2", "https://link3"],
  "inferredVersion": "3.6.0.4 or 'unknown'",
  "versionEvidence": "filename match | page text | changelog | unknown",
  "notes": "optional context about links"
}`;

    try {
        const response = await callLLM([
            { role: 'system', content: 'Output valid JSON only.' },
            { role: 'user', content: prompt }
        ], { temperature: 0 });
        
        const parsed = parseLLMJson(response);
        if (!parsed || !Array.isArray(parsed.downloadUrls)) {
            console.warn(`[DISTILL] Invalid response structure`);
            return null;
        }

        return parsed;
    } catch (e) {
        console.warn(`[DISTILL] Failed: ${e.message}`);
        return null;
    }
}

// ============================================================================
// Aggregation: Combine All Found Links
// ============================================================================

function aggregateVulnerableResults(knowledgeBase, exploit, disclosureDate) {
    const allUrls = new Set();
    let inferredVersion = "unknown";
    let versionEvidence = "unknown";
    let notes = [];
    
    for (const kb of knowledgeBase) {
        if (kb.findings?.downloadUrls) {
            for (const url of kb.findings.downloadUrls) {
                allUrls.add(url);
            }
        }
        if (kb.findings?.inferredVersion && kb.findings.inferredVersion !== "unknown") {
            inferredVersion = kb.findings.inferredVersion;
            versionEvidence = kb.findings.versionEvidence;
        }
        if (kb.findings?.notes) {
            notes.push(kb.findings.notes);
        }
    }
    
    const downloadUrls = Array.from(allUrls).slice(0, 5);
    const downloadUrlPrimary = selectPrimaryUrl(downloadUrls);
    
    return {
        name: (exploit.name || exploit).toString().trim(),
        version: inferredVersion,
        vulnerable: true,
        downloadUrls,
        downloadUrlPrimary,
        versionInference: {
            disclosureDate,
            vulnerableRange: `≤${inferredVersion}`,
            confidence: downloadUrls.length >= 3 ? "high" : downloadUrls.length >= 1 ? "medium" : "low",
            evidence: versionEvidence
        },
        notes: notes.slice(0, 3).join('; '),  // Limit notes length
        urlWarnings: downloadUrls.flatMap(url => validateDownloadUrl(url, inferredVersion)),
        sourceCredibility: downloadUrlPrimary ? scoreDownloadSource(downloadUrlPrimary) : "unknown"
    };
}

// ============================================================================
// Helper: Select Primary Download URL
// ============================================================================

function selectPrimaryUrl(urls) {
    if (!urls || urls.length === 0) return null;
    
    // Priority: archive.org direct > github releases > vendor direct > mirrors
    const hasDirectArchive = urls.find(url => 
        url.includes('archive.org/download') && !url.includes('web/')
    );
    if (hasDirectArchive) return hasDirectArchive;
    
    const hasGithubRelease = urls.find(url => 
        url.includes('github.com') && (url.includes('/releases/download/') || url.endsWith('.exe') || url.endsWith('.zip'))
    );
    if (hasGithubRelease) return hasGithubRelease;
    
    const hasDirectVendor = urls.find(url => 
        /vendor\.com|\.com\/downloads\/|\.com\/download\//i.test(url) && !/redirect|dyn-|php/i.test(url)
    );
    if (hasDirectVendor) return hasDirectVendor;
    
    return urls[0];
}

// ============================================================================
// Final Synthesis: Ansible-Ready Report
// ============================================================================

function synthesizeFinalReport(exploit, vulnerableSoftware) {
    const riskFlags = [];
    
    // Add risk flags
    if (vulnerableSoftware.downloadUrls.length === 0) {
        riskFlags.push("No download links found for vulnerable version");
    }
    if (vulnerableSoftware.urlWarnings?.length > 0) {
        riskFlags.push(...vulnerableSoftware.urlWarnings);
    }
    if (vulnerableSoftware.version === "unknown") {
        riskFlags.push("Version could not be inferred from available sources");
    }
    
    // Determine reproducibility verdict
    const hasLinks = vulnerableSoftware.downloadUrls.length >= 1;
    const hasGoodLinks = vulnerableSoftware.downloadUrls.length >= 3 && vulnerableSoftware.sourceCredibility !== "low";
    
    let verdict, confidence, rationale;
    if (hasGoodLinks) {
        verdict = "yes";
        confidence = "high";
        rationale = "Found 3+ credible download links for vulnerable version";
    } else if (hasLinks) {
        verdict = "partial";
        confidence = vulnerableSoftware.sourceCredibility === "high" ? "medium" : "low";
        rationale = `Found ${vulnerableSoftware.downloadUrls.length} link(s); credibility: ${vulnerableSoftware.sourceCredibility}`;
    } else {
        verdict = "no";
        confidence = "medium";
        rationale = "Could not find reliable download links for vulnerable version";
    }
    
    return {
        exploitName: exploit.name || exploit,  // Handle both string and object
        // FIX: Use exploit.msf_path directly (context is not in scope here)
        msfPath: exploit.msf_path,
        reproducibility: { verdict, confidence, rationale },
        minimumSetup: {
            os: determineRequiredOS(exploit),
            vulnerableSoftware,
            networkConfig: "NAT or bridged; allow inbound port for target service",
            privileges: "Local Administrator for install; service may run as LocalSystem"
        },
        automationBlueprint: {
            installSteps: generateInstallSteps(vulnerableSoftware),
            configSteps: ["Verify service is running and listening on expected port"],
            testSteps: [
                "Snapshot VM after install",
                "Run exploit → expect SUCCESS",
                "Document any deviations from expected behavior"
            ],
            testCommand: `msfconsole -q -x 'use ${exploit.msf_path}; set RHOSTS <target>; exploit'`,
            expectedResults: {
                success: "Exploit succeeds; session opened or service crashes"
            },
            rollbackNotes: "Revert to pre-install VM snapshot"
        },
        riskFlags,
        timestamp: new Date().toISOString(),
        status: 'complete',
        researchSummary: {
            linksFound: vulnerableSoftware.downloadUrls.length,
            primarySource: vulnerableSoftware.downloadUrlPrimary,
            versionConfidence: vulnerableSoftware.versionInference.confidence
        }
    };
}

// ============================================================================
// Helpers: OS Detection & Install Steps
// ============================================================================

function determineRequiredOS(exploit) {
    const desc = (exploit.description || "").toLowerCase();
    if (desc.includes('xp') || desc.includes('2003') || desc.includes('32-bit') || desc.includes('windows 7')) {
        return ["Windows 7 SP1 32-bit", "Windows Server 2003 R2 32-bit"];
    }
    return ["Windows Server 2016", "Windows Server 2019", "Windows Server 2022", "Windows 10", "Windows 11"];
}

function generateInstallSteps(software) {
    if (!software.downloadUrlPrimary) {
        return ["ERROR: No primary download URL available"];
    }
    const filename = software.downloadUrlPrimary.split('/').pop() || "installer.exe";
    return [
        `Download ${software.downloadUrlPrimary} to %TEMP%\\${filename}`,
        `Start-Process -Wait -FilePath %TEMP%\\${filename} -Args '/S'`,
        `Verify install: Test-Path 'C:\\Program Files\\${software.name}\\${software.name}.exe'`
    ];
}

// ============================================================================
// CLI Runner
// ============================================================================

if (import.meta.main) {
    console.log('✅ Prescreen module loaded');
    console.log('Usage: import { prescreenExploits } from "./scenario/prescreen.js"');
    console.log('');
    console.log('Example:');
    console.log('  const results = await prescreenExploits(exploitsArray, {');
    console.log('    searxngEndpoint: "http://localhost:8088",');
    console.log('    searxngTimeout: 3000');
    console.log('  });');
    main().catch(console.error);
}

async function main() {
    console.log('🔍 Exploit Prescreen — VM Reproducibility Research');
    console.log('==================================================\n');
    
    console.log(`📥 Loading exploits from ${INPUT_FILE}...`);
    const inputFile = Bun.file(INPUT_FILE);
    
    if (!(await inputFile.exists())) {
        console.error(`❌ File not found: ${INPUT_FILE}`);
        process.exit(1);
    }
    
    const exploits = JSON.parse(await inputFile.text());
    console.log(`✅ Loaded ${exploits.length} modules\n`);
    
    console.log('🚀 Starting agentic research loop...\n');
    const startTime = Date.now();
    
    const results = await prescreenExploits(exploits, {
        searxngEndpoint: process.env.SEARXNG_ENDPOINT || 'http://localhost:8088',
        searxngTimeout: parseInt(process.env.SEARXNG_TIMEOUT || '3000', 10)
    });
    
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    
    // Summary stats
    const completed = results.filter(r => r.status === 'complete').length;
    const errors = results.filter(r => r.status !== 'complete').length;
    const yesVerdict = results.filter(r => r.reproducibility?.verdict === 'yes').length;
    const partialVerdict = results.filter(r => r.reproducibility?.verdict === 'partial').length;
    
    console.log('\n📊 Research Summary');
    console.log('───────────────────');
    console.log(`Total processed: ${results.length}`);
    console.log(`✅ Complete: ${completed}`);
    console.log(`❌ Errors: ${errors}`);
    console.log(`🎯 Reproducible (yes): ${yesVerdict}`);
    console.log(`⚠️  Partially reproducible: ${partialVerdict}`);
    console.log(`⏱️  Elapsed: ${elapsed}s\n`);
    
    // Save results
    await $`mkdir -p ./output`;
    await Bun.write(OUTPUT_FILE, JSON.stringify(results, null, 2));
    console.log(`💾 Results saved to ${OUTPUT_FILE}`);
    
    // Print top candidates
    const ansibleReady = results.filter(r => 
        r.status === 'complete' && 
        (r.reproducibility?.verdict === 'yes' || r.reproducibility?.verdict === 'partial')
    );
    
    if (ansibleReady.length > 0) {
        console.log('\n🎯 Top Candidates for Ansible Automation Phase:');
        console.log('─────────────────────────────────────────────────');
        ansibleReady.slice(0, 5).forEach((r, i) => {
            console.log(`${i + 1}. ${r.exploitName}`);
            console.log(`   Path: ${r.msfPath}`);
            console.log(`   Verdict: ${r.reproducibility.verdict} (${r.reproducibility.confidence})`);
            console.log(`   Version: ${r.minimumSetup?.vulnerableSoftware?.version}`);
            console.log(`   Links: ${r.minimumSetup?.vulnerableSoftware?.downloadUrls?.length || 0} found`);
            console.log(`   Primary: ${r.minimumSetup?.vulnerableSoftware?.downloadUrlPrimary || 'N/A'}\n`);
        });
    }
    
    console.log('✅ Prescreen complete. Ready for Ansible ReAct loop.');
    return results;
}