#!/usr/bin/env bun

import { $ } from "bun";

const API_URL = process.env.LUDUS_API_URL
const API_KEY = process.env.LUDUS_API_KEY?.trim();
const RANGE_ID = process.env.LUDUS_RANGE_ID || "ty";

if (!API_KEY) {
  console.error("❌ Set LUDUS_API_KEY environment variable");
  process.exit(1);
}

console.log(`🔗 API: ${API_URL}`);
console.log(`📦 Range: ${RANGE_ID}\n`);

// Curl wrapper using Bun.$ (handles self-signed certs via -k)
async function apiCall(path, method = "GET", queryParams = {}) {
  const qs = new URLSearchParams(queryParams).toString();
  const url = `${API_URL}${path}${qs ? `?${qs}` : ""}`;
  
  console.log(`   → ${method} ${url}`);
  const result = await $`curl -sk -X ${method} -H "X-API-KEY: ${API_KEY}" -H "Content-Type: application/json" ${url}`.text();
  console.log(`   ← ${result.length} bytes`);
  
  if (!result.trim()) return null;
  try { return JSON.parse(result); } catch { return { _raw: result }; }
}

async function getVMs() {
  // ✅ CORRECT: GET /range?rangeID=ty [[11]]
  const data = await apiCall("/range", "GET", { rangeID: RANGE_ID });
  return data?.VMs || [];
}

async function deleteVM(proxmoxID) {
  // ✅ CORRECT: DELETE /vm/{proxmoxID} [[23]]
  await apiCall(`/vm/${proxmoxID}`, "DELETE");
}

async function main() {
  console.log("🔍 Scanning for Windows VMs...\n");
  
  const vms = await getVMs();
  console.log(`\n📋 Found ${vms.length} VM(s) in range '${RANGE_ID}'\n`);
  
  if (vms.length === 0) {
    console.log("⚠️  No VMs found. Verify:");
    console.log(`   curl -sk -H "X-API-KEY: $LUDUS_API_KEY" "${API_URL}/range?rangeID=${RANGE_ID}" | jq`);
    return;
  }
  
  const windowsVMs = [];
  
  for (const vm of vms) {
    console.log(`   • ${vm.name} (ID: ${vm.proxmoxID}, Router: ${!!vm.isRouter})`);
    
    // 🔒 Skip router
    if (vm.isRouter === true) {
      console.log(`     🔒 Skipping router`);
      continue;
    }
    // 🔒 Skip Kali
    if (vm.name?.includes("attacker-kali")) {
      console.log(`     🔒 Skipping Kali`);
      continue;
    }
    // 🎯 Target Windows: ty-win*
    if (vm.name?.startsWith(`${RANGE_ID}-win`)) {
      windowsVMs.push({ proxmoxID: vm.proxmoxID, name: vm.name, ip: vm.ip || "N/A" });
      console.log(`     🎯 Marked for deletion`);
    }
  }
  
  console.log();
  
  if (windowsVMs.length === 0) {
    console.log("✅ No Windows VMs found — nothing to clean up");
    return;
  }
  
  console.log(`🗑️  Deleting ${windowsVMs.length} Windows VM(s):\n`);
  
  for (const vm of windowsVMs) {
    try {
      console.log(`🗑️  Destroying: ${vm.name} (Proxmox ID: ${vm.proxmoxID})...`);
      await deleteVM(vm.proxmoxID);
      console.log(`✅ Deleted: ${vm.name}`);
    } catch (err) {
      console.error(`❌ Failed: ${vm.name} — ${err.message}`);
    }
  }
  
  console.log("\n🎉 Cleanup complete! Router and Kali preserved.");
}

if (import.meta.main) {
  main().catch((err) => {
    console.error("\n❌ Fatal error:", err.message);
    process.exit(1);
  });
}