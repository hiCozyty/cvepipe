#!/usr/bin/env bun

import { $ } from "bun";

const API_URL = (process.env.LUDUS_API_URL || "").trim().replace(/\/$/, "");
const API_KEY = process.env.LUDUS_API_KEY?.trim();
const RANGE_ID = process.env.LUDUS_RANGE_ID || "ty";

if (!API_KEY) {
  console.error("❌ Set LUDUS_API_KEY environment variable");
  process.exit(1);
}

console.log(`🔗 API: ${API_URL}`);
console.log(`📦 Range: ${RANGE_ID}\n`);

const WINDOWS_TEMPLATES = {
  win10: { template: "win10-1507-x64-enterprise-template", hostname: "WIN10", ip_last_octet: 21 },
  win11: { template: "win11-21h2-x64-enterprise-template", hostname: "WIN11", ip_last_octet: 22 },
  win2012: { template: "win2012r2-server-x64-template", hostname: "WIN2012-SRV", ip_last_octet: 23 },
  win2016: { template: "win2016-server-x64-template", hostname: "WIN2016-SRV", ip_last_octet: 24 },
  win2019: { template: "win2019-server-x64-no-security-updates-template", hostname: "WIN2019-SRV", ip_last_octet: 25 },
  win2022: { template: "win2022-server-x64-template", hostname: "WIN2022-SRV", ip_last_octet: 20 },
};

async function apiCall(path, method = "GET", queryParams = {}, body = null, contentType = "application/json") {
  const qs = new URLSearchParams(queryParams).toString();
  const url = `${API_URL}${path}${qs ? `?${qs}` : ""}`;
  
  console.log(`   → ${method} ${url}`);
  
  let result;
  if (body !== null) {
    const escapedBody = String(body).replace(/'/g, "'\\''");
    result = await $`bash -c "curl -sk -X ${method} -H 'X-API-KEY: ${API_KEY}' -H 'Content-Type: ${contentType}' -d '${escapedBody}' '${url}'"`.text();
  } else {
    result = await $`curl -sk -X ${method} -H "X-API-KEY: ${API_KEY}" -H "Content-Type: ${contentType}" ${url}`.text();
  }
  
  console.log(`   ← ${result.length} bytes`);
  
  if (!result.trim()) return null;
  if (contentType === "application/json") {
    try { return JSON.parse(result); } catch { return { _raw: result }; }
  }
  return result;
}

async function getVMs() {
  const data = await apiCall("/range", "GET", { rangeID: RANGE_ID });
  return data?.VMs || [];
}

async function deleteVM(proxmoxID) {
  await apiCall(`/vm/${proxmoxID}`, "DELETE");
}

async function deleteWindowsVMs(windowsType) {
  const vms = await getVMs();
  const toDelete = [];
  
  for (const vm of vms) {
    if (vm.isRouter === true) continue;
    if (vm.name?.includes("attacker-kali")) continue;
    if (vm.name === `${RANGE_ID}-${windowsType}`) {
      toDelete.push({ proxmoxID: vm.proxmoxID, name: vm.name });
    }
    if (vm.name?.startsWith(`${RANGE_ID}-win`) && !vm.name.includes("attacker")) {
      if (!toDelete.find(v => v.proxmoxID === vm.proxmoxID)) {
        toDelete.push({ proxmoxID: vm.proxmoxID, name: vm.name });
      }
    }
  }
  
  for (const vm of toDelete) {
    console.log(`🗑️  Cleaning up: ${vm.name} (ID: ${vm.proxmoxID})`);
    try {
      await deleteVM(vm.proxmoxID);
      console.log(`✅ Deleted: ${vm.name}`);
    } catch (err) {
      console.error(`⚠️  Failed: ${vm.name} — ${err.message}`);
    }
  }
}

function generateYaml({ includeKali, windowsType }) {
  const winConfig = WINDOWS_TEMPLATES[windowsType];
  if (!winConfig) throw new Error(`Unknown: ${windowsType}`);

  const entries = [];
  if (includeKali) {
    entries.push(`  - vm_name: "{{ range_id }}-attacker-kali"
    hostname: attacker-kali
    template: kali-x64-desktop-template
    vlan: 99
    ip_last_octet: 1
    ram_gb: 4
    cpus: 2
    linux: true`);
  }
  entries.push(`  - vm_name: "{{ range_id }}-${windowsType}"
    hostname: ${winConfig.hostname}
    template: ${winConfig.template}
    vlan: 99
    ip_last_octet: ${winConfig.ip_last_octet}
    ram_gb: 4
    cpus: 2
    windows:
      sysprep: false`);

  return `ludus:\n${entries.join("\n\n")}\n`;
}

async function setRangeConfig(yamlContent) {
  await apiCall("/range/config", "PUT", {}, yamlContent, "application/yaml");
}

async function deployRange() {
  return await apiCall("/range/deploy", "POST");
}

// ✅ Poll deployment status until complete (or timeout)
async function waitForDeployment(timeoutMs = 300000, intervalMs = 5000) {
  const start = Date.now();
  console.log(`\n⏳ Waiting for deployment (timeout: ${timeoutMs/1000}s)...`);
  
  while (Date.now() - start < timeoutMs) {
    const data = await apiCall("/range", "GET", { rangeID: RANGE_ID });
    const status = data?.deploymentStatus || data?.status || "unknown";
    const progress = data?.deploymentProgress || "N/A";
    
    console.log(`   📊 Status: ${status} ${progress !== "N/A" ? `(${progress})` : ""}`);
    
    if (status === "READY" || status === "SUCCESS" || status === "COMPLETE") {
      console.log("✅ Deployment complete!");
      return true;
    }
    if (status === "ERROR" || status === "FAILED") {
      console.error("❌ Deployment failed");
      return false;
    }
    
    await new Promise(res => setTimeout(res, intervalMs));
  }
  
  console.warn("⚠️  Timeout waiting for deployment");
  return false;
}

async function main() {
  const windowsType = Bun.argv[2];
  const saveYaml = Bun.argv[3] === "--save-yaml";
  const waitForDeploy = Bun.argv[3] === "--wait" || Bun.argv[4] === "--wait";
  
  if (!windowsType || !WINDOWS_TEMPLATES[windowsType]) {
    console.log(`Usage: bun init.js <windows-type> [--save-yaml] [--wait]`);
    console.log(`Available: ${Object.keys(WINDOWS_TEMPLATES).join(", ")}`);
    console.log(`Options:`);
    console.log(`  --save-yaml  Keep local copy of generated config`);
    console.log(`  --wait       Poll until deployment completes (default: fire-and-forget)`);
    process.exit(1);
  }

  console.log(`🚀 Initializing: Kali (if missing) + ${windowsType}\n`);

  // Check VMs
  console.log("🔍 Checking current VMs...");
  const currentVMs = await getVMs();
  const kaliExists = currentVMs.some(vm => vm.name?.includes("attacker-kali"));
  console.log(kaliExists ? `✅ Kali exists — skipping` : `⏳ Kali not found — will create`);

  // Cleanup Windows VMs
  console.log(`\n🧹 Cleaning up ${windowsType}...`);
  await deleteWindowsVMs(windowsType);

  // Generate & apply config (no local file unless --save-yaml)
  console.log("\n📝 Applying configuration...");
  const yamlContent = generateYaml({ includeKali: !kaliExists, windowsType });
  
  if (saveYaml) {
    await Bun.write("windows-range.yml", yamlContent);
    console.log(`💾 Saved to windows-range.yml`);
  }
  
  await setRangeConfig(yamlContent);
  console.log("✅ Config applied");

  // Deploy
  console.log("\n🚀 Deploying...");
  await deployRange();
  console.log("✅ Deployment triggered");

  // Optional: wait for completion
  if (waitForDeploy) {
    const success = await waitForDeployment();
    if (!success) process.exit(1);
  } else {
    console.log("💡 Deployment running in background");
    console.log(`💡 Monitor: ssh root@192.168.1.150 'ludus range status'`);
  }

  console.log("\n🎉 Done!");
  console.log(`   • Kali: ${kaliExists ? "preserved ✅" : "created 🆕"}`);
  console.log(`   • ${windowsType}: ${waitForDeploy ? "deployed & verified ✅" : "deployed 🚀"}`);
}

if (import.meta.main) {
  main().catch((err) => {
    console.error("\n❌ Fatal error:", err.message);
    process.exit(1);
  });
}