/**
 * Stage 1: Windows CVE Fetcher — Data-Driven Version
 * Runtime: Bun
 * Strategy: Server CVSS filter + Client CPE parsing (structural, not wildcards)
 */

const CONFIG = {
  lookbackDays: 120,
  cvssVector: "AV:N/PR:N/UI:N",  // ✅ Server-side: reliable
  cweWhitelist: new Set(["CWE-78","CWE-77","CWE-94","CWE-917","CWE-502","CWE-434","CWE-287","CWE-306","CWE-798","CWE-1390","CWE-290","CWE-22","CWE-89"]),
  cweBlacklist: new Set(["CWE-79","CWE-400","CWE-770","CWE-476","CWE-200","CWE-918","CWE-611","CWE-416","CWE-787","CWE-125","CWE-190","CWE-362","CWE-732"]),
};

const NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const API_KEY = process.env.NVD_API_KEY ?? "";
const PAGE_SIZE = 2000;

const fmt = d => d.toISOString().slice(0,19) + "Z";

function* dateChunks(daysBack, max = 120) {
  const end = new Date(), start = new Date(end);
  start.setDate(start.getDate() - daysBack);
  while (start < end) {
    const chunkEnd = new Date(Math.min(start.getTime() + max*864e5, end.getTime()));
    yield { pubStartDate: fmt(start), pubEndDate: fmt(chunkEnd) };
    start.setDate(start.getDate() + max);
  }
}

function getCVSSv3(m) { return (m?.cvssMetricV31 ?? m?.cvssMetricV30 ?? [])[0]?.cvssData ?? null; }
function getCWEs(cve) { const o=[]; for(const w of cve.weaknesses??[]) for(const d of w.description??[]) if(d.value)o.push(d.value); return o; }
function checkCWEs(cwes) {
  if(!cwes.length) return {pass:true,priority:false};
  let bl=false,wl=false;
  for(const c of cwes){ if(CONFIG.cweBlacklist.has(c))bl=true; if(CONFIG.cweWhitelist.has(c))wl=true; }
  if(bl) return {pass:false,priority:false};
  return {pass:true,priority:wl};
}

// ✅ Parse CPE structurally — based on real NVD format
function parseCpe(uri) {
  if(!uri?.toLowerCase().startsWith("cpe:2.3:")) return null;
  const p = uri.split(":");
  if(p.length < 12) return null;
  return { part:p[2], vendor:p[3], product:p[4], version:p[5], target_sw:p[10], raw:uri };
}

// ✅ Windows detection: structural rules, NO hardcoded product lists
function isWindowsCpe(cpe) {
  if(!cpe) return false;
  // Windows OS: o + microsoft + product^windows
  if(cpe.part==="o" && cpe.vendor==="microsoft" && cpe.product?.startsWith("windows")) return true;
  // Microsoft apps: assume Windows unless target_sw explicitly says otherwise
  if(cpe.vendor==="microsoft" && cpe.part==="a" && (!cpe.target_sw || cpe.target_sw==="*" || !cpe.target_sw.toLowerCase().includes("linux"))) return true;
  return false;
}

function hasWindowsMatch(cve) {
  for(const cfg of cve.configurations??[]) {
    for(const node of cfg.nodes??[]) {
      for(const m of node.cpeMatch??[]) {
        if(!m.vulnerable) continue;
        const parsed = parseCpe(m.criteria);
        if(parsed && isWindowsCpe(parsed)) return true;
      }
    }
  }
  return false;
}

async function fetchPage(params) {
  const url = new URL(NVD);
  for(const[k,v] of Object.entries(params)) if(v!=null) url.searchParams.set(k,String(v));
  const headers = { "User-Agent": "cvepipe/1.0" };
  if(API_KEY) headers.apiKey = API_KEY;
  const res = await fetch(url,{headers});
  if(!res.ok) throw new Error(`NVD ${res.status}: ${await res.text()}`);
  return res.json();
}

async function fetchAll(dateRange) {
  const all=[]; let idx=0, total=Infinity;
  while(idx < total) {
    process.stdout.write(` [${idx}]...`);
    // ✅ ONLY cvssV3Metrics server-side — virtualMatchString is useless per real data
    const data = await fetchPage({ ...dateRange, startIndex:idx, resultsPerPage:PAGE_SIZE, cvssV3Metrics:CONFIG.cvssVector });
    total = data.totalResults??0;
    const page = data.vulnerabilities??[];
    all.push(...page);
    console.log(` +${page.length} (total:${total})`);
    idx += PAGE_SIZE;
    if(idx<total) await Bun.sleep(1000);
  }
  return all;
}

async function main() {
  console.log(`🎯 Fetching: CVSS=${CONFIG.cvssVector} + Windows (client-side CPE parse)\n`);
  
  let all=[];
  for(const chunk of dateChunks(CONFIG.lookbackDays)) {
    console.log(`📦 ${chunk.pubStartDate} → ${chunk.pubEndDate}`);
    all.push(...await fetchAll(chunk));
  }
  
  console.log(`\n✅ Fetched (CVSS-filtered): ${all.length}`);
  
  let pri=0, unk=0, bl=0, noWin=0;
  for(const v of all) {
    const cve = v.cve; if(!cve) continue;
    const cwes = getCWEs(cve);
    const res = checkCWEs(cwes);
    if(!res.pass){ bl++; continue; }
    if(!hasWindowsMatch(cve)){ noWin++; continue; }
    if(res.priority) pri++; else unk++;
  }
  
  const total = pri + unk;
  console.log("\n═══════════════════════════");
  console.log("  STAGE 1 RESULTS");
  console.log("═══════════════════════════");
  console.log(`  Total hits:     ${total}`);
  console.log(`    └ Priority:   ${pri}`);
  console.log(`    └ Unknown:    ${unk}`);
  console.log(`    └ Blacklisted:${bl}`);
  console.log(`    └ Non-Windows:${noWin}`);
  console.log("═══════════════════════════");
  return { total, pri, unk };
}

main().catch(e=>{ console.error("💥",e.message); process.exit(1); });