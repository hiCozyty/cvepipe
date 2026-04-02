#!/usr/bin/env bun

/**
 * Exploit Prescreen: VM Reproducibility Research Agent
 * Filters exploits and performs agentic deep research via SearXNG + LLM
 * 
 * FEATURES:
 * - Summarizing layer for iterative context preservation
 * - URL deduplication & normalization
 * - Structured metadata extraction from Metasploit descriptions
 * - Robust JSON parsing with fallbacks
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
// Helpers
// ============================================================================

function parseLLMJson(response) {
    try {
        const cleaned = response.replace(/```json?\n?/g, '').replace(/```\s*$/g, '').trim();
        return JSON.parse(cleaned);
    } catch (e) {
        try {
            // Fix trailing commas
            const fixed = response.replace(/,\s*([\]}])/g, '$1').replace(/```json?\n?/g, '').replace(/```\s*$/g, '').trim();
            return JSON.parse(fixed);
        } catch {
            return null;
        }
    }
}

function normalizeUrl(url) {
    if (!url) return '';
    return url.replace(/\/$/, '').split('?')[0].replace(/#.*$/, '').toLowerCase();
}

function extractProductMetadata(exploit) {
    const desc = exploit.description || "";
    const vendorMatch = desc.match(/by ([A-Z][a-zA-Z0-9\- ]+)/);
    const versionMatch = desc.match(/Tested against ([\d.]+)/);
    const productMatch = desc.match(/utilizes the ([^,]+)'s/);
    
    return {
        vendor: vendorMatch ? vendorMatch[1].trim() : null,
        product: productMatch ? productMatch[1].trim() : null,
        testedVersion: versionMatch ? versionMatch[1] : null,
        platform: exploit.platform?.[0] || "unknown",
        arch: exploit.arch || []
    };
}

// Summarizing layer: condenses findings for next iteration
function summarizeFindings(query, findings) {
    if (!findings?.downloadUrls?.length) return `Query: "${query}" → 0 links found`;
    
    const ver = findings.inferredVersion || "unknown";
    const urls = findings.downloadUrls.slice(0, 2).join(", ");
    const notes = findings.notes ? findings.notes.slice(0, 120) : "";
    const warnings = findings.urlWarnings?.join("; ") || "";
    
    return `Query: "${query}" → v${ver} (${findings.downloadUrls.length} links) | URLs: ${urls} | ${notes}${warnings ? ` ⚠️ ${warnings}` : ""}`;
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

function sanitizeSnippet(text) {
    if (!text) return "";
    return text.replace(/<[^>]*>/gm, '').replace(/\s+/g, ' ').trim();
}

async function searchSearXNG(query, config = {}) {
    const endpoint = config.endpoint || SEARXNG_ENDPOINT;
    const timeout = config.timeout || SEARXNG_TIMEOUT;
    
    try {
        const url = `${endpoint}/search?q=${encodeURIComponent(query)}&format=json`;
        const response = await fetch(url, { signal: AbortSignal.timeout(timeout) });
        const data = await response.json();
        
        return (data.results || [])
            .filter(r => r.content && r.content.length > 20)
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

async function extractArticleText(url) {
    if (!url) return "";
    try {
        const response = await fetch(url, {
            headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0' }
        });
        const html = await response.text();
        
        const virtualConsole = new VirtualConsole();
        virtualConsole.on("error", () => {});
        
        const dom = new JSDOM(html, { url, virtualConsole });
        const reader = new Readability(dom.window.document);
        const article = reader.parse();
        
        return article?.textContent?.replace(/\n\s*\n/g, '\n').replace(/[ \t]+/g, ' ').trim() || "";
    } catch (error) {
        console.warn(`[EXTRACT] Could not scrape ${url}: ${error.message}`);
        return "";
    }
}

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

function validateDownloadUrl(url, version) {
    const warnings = [];
    if (/redirect|dyn-|download\.php|click\.php|postdq\.php/i.test(url)) {
        warnings.push("URL is a redirector; may require browser/cookies");
    }
    if (/\.(apk|ipa|bin|img|tar\.gz)$/i.test(url) || /android|ios|firmware|routeros/i.test(url)) {
        warnings.push("Non-Windows platform detected; likely wrong binary");
    }
    return warnings;
}

// ============================================================================
// Main Entry
// ============================================================================

export async function prescreenExploits(exploits, options = {}) {
    const results = [];
    const config = {
        searxngEndpoint: options.searxngEndpoint || SEARXNG_ENDPOINT,
        searxngTimeout: options.searxngTimeout || SEARXNG_TIMEOUT
    };
    
    const candidates = exploits.filter(e => e.replicable === true && e.access_type === 'initial_foothold');
    console.log(`🎯 Prescreening ${candidates.length}/${exploits.length} exploits for VM reproducibility...`);
    
    for (const exploit of candidates) {
        try {
            console.log(`🔍 Researching: ${exploit.name || 'unknown'}`);
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
            console.error(`❌ Failed to research ${exploit.name || 'unknown'}: ${error.message}`);
            results.push({
                exploitName: exploit.name || 'unknown',
                msfPath: exploit.msf_path || 'unknown',
                status: 'error',
                error: error.message,
                timestamp: new Date().toISOString()
            });
        }
    }
    return results;
}

// ============================================================================
// Research Loop
// ============================================================================

async function analyzeExploitReproducibility(exploit, config, maxDepth = MAX_RESEARCH_DEPTH) {
    const metadata = extractProductMetadata(exploit);
    const disclosureDate = exploit.disclosed || "unknown";
    
    const context = {
        exploit: { ...exploit, metadata, disclosureDate }, 
        knowledgeBase: [],
        searchedQueries: new Set(),
        analyzedUrls: new Set()
    };
    
    console.log(`  🎯 Finding vulnerable version downloads (≤ ${disclosureDate}) | Target: ${metadata.vendor || 'unknown'} / ${metadata.testedVersion || 'unknown'}`);
    
    let depth = 0;
    let isComplete = false;
    
    while (!isComplete && depth < maxDepth) {
        const queryPlan = await generateVulnerableQueries(context, depth);
        
        if (queryPlan.isComplete) isComplete = true;
        else {
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
                            } catch { return { ...res, fullText: null }; }
                        })
                    );
                    
                    const validResults = enrichedResults.filter(r => r.fullText);
                    const newResults = validResults.filter(r => {
                        if (context.analyzedUrls.has(normalizeUrl(r.url))) return false;
                        context.analyzedUrls.add(normalizeUrl(r.url));
                        return true;
                    });
                    
                    if (!newResults.length) continue;
                    
                    const distilled = await distillVulnerableLinks(newResults, exploit, query, disclosureDate, metadata);
                    if (distilled?.downloadUrls?.length > 0) {
                        const summary = summarizeFindings(query, distilled);
                        context.knowledgeBase.push({ query, findings: distilled, summary });
                    }
                } catch (err) {
                    console.warn(`[QUERY] Failed "${query}": ${err.message}`);
                }
            }
            depth++;
            console.log(`🔄 Iteration ${depth}/${maxDepth} complete for ${exploit.name}`);
        }
    }
    
    const vulnerableSoftware = aggregateVulnerableResults(context.knowledgeBase, exploit, disclosureDate);
    return synthesizeFinalReport(exploit, vulnerableSoftware);
}

// ============================================================================
// Query Generation
// ============================================================================

async function generateVulnerableQueries(context, iteration) {
    const { exploit, knowledgeBase } = context;
    const { metadata, disclosureDate } = exploit;  
        
    // Build rich, compact context from previous iterations
    const historyCap = 4;
    const recentHistory = knowledgeBase.slice(-historyCap).map((k, i) => 
        `[${i + knowledgeBase.length - Math.min(knowledgeBase.length, historyCap) + 1}] ${k.summary}`
    ).join('\n');
    
    const totalCount = knowledgeBase.reduce((s, k) => s + (k.findings?.downloadUrls?.length || 0), 0);
    const contextHeader = `📊 PROGRESS: ${totalCount} total links found across ${knowledgeBase.length} iterations.\n\nRECENT FINDINGS:\n${recentHistory || 'None yet.'}`;
    
    const prompt = `You are researching DOWNLOAD LINKS for the VULNERABLE version of this software.

PRODUCT METADATA (from Metasploit):
- Vendor: ${metadata.vendor || 'unknown'}
- Product: ${metadata.product || 'unknown'}
- Tested Version: ${metadata.testedVersion || 'unknown'}
- Platform: ${metadata.platform} (${metadata.arch.join(', ')})
- Disclosure Date: ${disclosureDate}

${contextHeader}

YOUR TASK:
Generate 1-3 NEW search queries to find download links for the vulnerable version (≤ ${disclosureDate}).
DO NOT repeat queries or target versions/URLs already found above.

SEARCH STRATEGY:
- Focus on vendor sites, archive.org, mirrors, blogs, software directories
- Use date ranges: "software download 2020..2022", "setup.exe 2022"
- Look for exact filenames: "${metadata.product || 'Software'}Setup_${metadata.testedVersion || 'X.Y.Z'}.exe"
- EXCLUDE: .apk, .ipa, firmware, Linux packages, Android/iOS apps

Respond with VALID JSON ONLY:
{
  "isComplete": boolean,
  "reasoning": "1 sentence on why we have enough info OR need more",
  "queries": ["query1", "query2"]
}`;

    try {
        const response = await callLLM([
            { role: 'system', content: 'Output valid JSON only. No markdown.' },
            { role: 'user', content: prompt }
        ], { temperature: 0.1 });
        
        const parsed = parseLLMJson(response);
        if (!parsed || !Array.isArray(parsed.queries)) {
            return { isComplete: iteration >= 4, reasoning: 'Fallback', queries: [] };
        }
        
        return {
            isComplete: parsed.isComplete === true,
            reasoning: parsed.reasoning || '',
            queries: parsed.queries.slice(0, 3)
        };
    } catch (e) {
        console.warn(`[QUERY_GEN] Failed: ${e.message}`);
        return { isComplete: iteration >= 4, reasoning: 'Fallback', queries: [] };
    }
}

// ============================================================================
// Distillation
// ============================================================================

async function distillVulnerableLinks(results, exploit, query, disclosureDate, metadata) {
    const contentBlocks = results.map((r, i) => 
        `SOURCE ${i+1} [${r.url}]:\n${(r.fullText || '').slice(0, 20000)}\n---`
    ).join('\n\n');

    const prompt = `Extract DOWNLOAD LINKS for the VULNERABLE version of this software.

TARGET METADATA:
- Vendor: ${metadata.vendor || 'unknown'}
- Target Version: ${metadata.testedVersion || 'unknown'}
- Platform: ${metadata.platform}
- Disclosure Date: ${disclosureDate}

CONTENT:
${contentBlocks}

EXTRACT:
✅ Find AT LEAST 3 download URLs for the vulnerable version (≤ ${disclosureDate})
✅ Infer version from filename, page text, or changelog
✅ Note if URL is direct download or redirector
✅ EXCLUDE non-Windows binaries (.apk, .ipa, firmware, Linux)
✅ Flag vendor/version mismatches

Respond with VALID JSON:
{
  "downloadUrls": ["https://link1", "https://link2", "https://link3"],
  "inferredVersion": "3.1.1.12 or 'unknown'",
  "versionEvidence": "filename match | page text | changelog | unknown",
  "notes": "optional context (keep under 150 chars)"
}`;

    try {
        const response = await callLLM([
            { role: 'system', content: 'Output valid JSON only.' },
            { role: 'user', content: prompt }
        ], { temperature: 0 });
        
        const parsed = parseLLMJson(response);
        if (!parsed || !Array.isArray(parsed.downloadUrls)) return null;
        return parsed;
    } catch (e) {
        console.warn(`[DISTILL] Failed: ${e.message}`);
        return null;
    }
}

// ============================================================================
// Aggregation
// ============================================================================

function aggregateVulnerableResults(knowledgeBase, exploit, disclosureDate) {
    const allUrls = new Set();
    let inferredVersion = "unknown";
    let versionEvidence = "unknown";
    let notes = [];
    let urlWarnings = [];
    
    for (const kb of knowledgeBase) {
        if (kb.findings?.downloadUrls) {
            for (const url of kb.findings.downloadUrls) allUrls.add(url);
        }
        if (kb.findings?.inferredVersion && kb.findings.inferredVersion !== "unknown") {
            inferredVersion = kb.findings.inferredVersion;
            versionEvidence = kb.findings.versionEvidence;
        }
        if (kb.findings?.notes) notes.push(kb.findings.notes);
    }
    
    const downloadUrls = Array.from(allUrls).slice(0, 5);
    const downloadUrlPrimary = selectPrimaryUrl(downloadUrls);
    
    return {
        name: exploit.name || 'unknown',
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
        notes: notes.slice(0, 3).join('; '),
        urlWarnings: downloadUrls.flatMap(url => validateDownloadUrl(url, inferredVersion)),
        sourceCredibility: downloadUrlPrimary ? scoreDownloadSource(downloadUrlPrimary) : "unknown"
    };
}

function selectPrimaryUrl(urls) {
    if (!urls?.length) return null;
    if (urls.find(u => u.includes('archive.org/download') && !u.includes('web/'))) {
        return urls.find(u => u.includes('archive.org/download'));
    }
    if (urls.find(u => u.includes('github.com') && (u.includes('/releases/') || /\.(exe|msi|zip)$/i.test(u)))) {
        return urls.find(u => u.includes('github.com'));
    }
    if (urls.find(u => /vendor\.com|\.com\/downloads\//i.test(u) && !/redirect|php/i.test(u))) {
        return urls.find(u => /vendor\.com|\.com\/downloads\//i.test(u));
    }
    return urls[0];
}

// ============================================================================
// Final Synthesis
// ============================================================================

function synthesizeFinalReport(exploit, vulnerableSoftware) {
    const riskFlags = [];
    if (vulnerableSoftware.downloadUrls.length === 0) riskFlags.push("No download links found for vulnerable version");
    if (vulnerableSoftware.urlWarnings?.length > 0) riskFlags.push(...vulnerableSoftware.urlWarnings);
    if (vulnerableSoftware.version === "unknown") riskFlags.push("Version could not be inferred from available sources");
    
    const hasLinks = vulnerableSoftware.downloadUrls.length >= 1;
    const hasGoodLinks = vulnerableSoftware.downloadUrls.length >= 3 && vulnerableSoftware.sourceCredibility !== "low";
    
    let verdict, confidence, rationale;
    if (hasGoodLinks) {
        verdict = "yes"; confidence = "high";
        rationale = "Found 3+ credible download links for vulnerable version";
    } else if (hasLinks) {
        verdict = "partial";
        confidence = vulnerableSoftware.sourceCredibility === "high" ? "medium" : "low";
        rationale = `Found ${vulnerableSoftware.downloadUrls.length} link(s); credibility: ${vulnerableSoftware.sourceCredibility}`;
    } else {
        verdict = "no"; confidence = "medium";
        rationale = "Could not find reliable download links for vulnerable version";
    }
    
    return {
        exploitName: exploit.name || exploit,
        msfPath: exploit.msf_path,
        reproducibility: { verdict, confidence, rationale },
        minimumSetup: {
            os: exploit.description?.toLowerCase().includes('xp') || exploit.description?.toLowerCase().includes('2003') 
                ? ["Windows 7 SP1 32-bit", "Windows Server 2003 R2 32-bit"] 
                : ["Windows Server 2016", "Windows Server 2019", "Windows Server 2022", "Windows 10", "Windows 11"],
            vulnerableSoftware,
            networkConfig: "NAT or bridged; allow inbound port for target service",
            privileges: "Local Administrator for install; service may run as LocalSystem"
        },
        automationBlueprint: {
            installSteps: vulnerableSoftware.downloadUrlPrimary ? [
                `Download ${vulnerableSoftware.downloadUrlPrimary} to %TEMP%\\${vulnerableSoftware.downloadUrlPrimary.split('/').pop() || 'installer.exe'}`,
                `Start-Process -Wait -FilePath %TEMP%\\${vulnerableSoftware.downloadUrlPrimary.split('/').pop()} -Args '/S'`,
                `Verify install path in vendor docs or registry`
            ] : ["ERROR: No primary download URL available"],
            configSteps: ["Verify service is running and listening on expected port"],
            testSteps: ["Snapshot VM after install", "Run exploit → expect SUCCESS", "Document deviations"],
            testCommand: `msfconsole -q -x 'use ${exploit.msf_path}; set RHOSTS <target>; exploit'`,
            expectedResults: { success: "Exploit succeeds; session opened or service crashes" },
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
    
    await $`mkdir -p ./output`;
    await Bun.write(OUTPUT_FILE, JSON.stringify(results, null, 2));
    console.log(`💾 Results saved to ${OUTPUT_FILE}`);
    
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