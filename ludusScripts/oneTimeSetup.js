#!/usr/bin/env bun
// usage bun run oneTimeSetup.js <windows-type>

import { $ } from "bun";

const API_URL = process.env.LUDUS_API_URL
const API_KEY = process.env.LUDUS_API_KEY?.trim();
const RANGE_ID = process.env.LUDUS_RANGE_ID || "ty";
const LUDUS_HOST = process.env.LUDUS_HOST;
const BASE_SNAPSHOT_NAME = "base-clean";

if (!API_KEY) { console.error("❌ Set LUDUS_API_KEY"); process.exit(1); }
console.log(`🔗 API: ${API_URL}`);
console.log(`📦 Range: ${RANGE_ID}\n`);

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

// API call via curl (handles self-signed certs with -k)
async function apiCall(path, method = "GET", queryParams = {}, body = null, contentType = "application/json") {
  const qs = new URLSearchParams(queryParams).toString();
  const url = `${API_URL}${path}${qs ? `?${qs}` : ""}`;
  console.log(`   → ${method} ${url}`);
  
  let result;
  if (body !== null) {
    const serialized = contentType === "application/json" ? JSON.stringify(body) : String(body);
    const escaped = serialized.replace(/'/g, "'\\''");
    result = await $`bash -c "curl -sk -X ${method} -H 'X-API-KEY: ${API_KEY}' -H 'Content-Type: ${contentType}' -d '${escaped}' '${url}'"`.text();

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

async function deleteOtherWindowsVMs(keepType) {
  const vms = await getVMs();
  for (const vm of vms) {
    if (vm.isRouter === true) continue;
    if (vm.name?.includes("attacker-kali")) continue;
    if (vm.name?.startsWith(`${RANGE_ID}-win`) && !vm.name.endsWith(keepType)) {
      console.log(`🗑️  Deleting: ${vm.name}`);
      await deleteVM(vm.proxmoxID);
    }
  }
}

function generateYaml({ includeKali, windowsType }) {
  const win = WINDOWS_TEMPLATES[windowsType];
  if (!win) throw new Error(`Unknown: ${windowsType}`);
  const entries = [];
  if (includeKali) entries.push(`  - vm_name: "{{ range_id }}-attacker-kali"
    hostname: attacker-kali
    template: kali-x64-desktop-template
    vlan: 99
    ip_last_octet: 1
    ram_gb: 4
    cpus: 2
    linux: true`);
  entries.push(`  - vm_name: "{{ range_id }}-${windowsType}"
    hostname: ${win.hostname}
    template: ${win.template}
    vlan: 99
    ip_last_octet: ${win.ip_last_octet}
    ram_gb: 4
    cpus: 2
    windows:
      sysprep: false`);
  return `ludus:\n${entries.join("\n\n")}\n`;
}

async function setRangeConfig(yaml) {
  await apiCall("/range/config", "PUT", {}, yaml, "application/yaml");
}

async function deployRange() {
  await apiCall("/range/deploy", "POST");
}

// ✅ Check if snapshot exists via API: GET /snapshots
async function snapshotExists(proxmoxID, snapshotName) {
  try {
    // GET /snapshots?vmid={id} returns list of snapshots for that VM
    const data = await apiCall("/snapshots/list", "GET", { rangeID: RANGE_ID, vmids: proxmoxID });    
    console.log(`   🔎 Snapshot API response:`, JSON.stringify(data)); 
    const snapshots = data?.snapshots || data || [];
    return snapshots.some(s => s.name === snapshotName || s.snapname === snapshotName);
  } catch {
    return false;
  }
}

// ✅ Create snapshot via API: POST /snapshots/create
async function createSnapshot(proxmoxID, snapshotName) {
  console.log(`📸 Creating snapshot "${snapshotName}" on VM ${proxmoxID}...`);
  
  const body = {
    vmids: [proxmoxID],
    name: snapshotName,
    description: `Base clean state for ${RANGE_ID}-${snapshotName}`,
    includeRAM: false,
  };
  const result = await apiCall("/snapshots/create", "POST", { rangeID: RANGE_ID }, body, "application/json");
  if (result?.errors?.length) {
    throw new Error(`Snapshot failed on VM ${proxmoxID}: ${result.errors[0].error}`);
  }
  console.log(`✅ Snapshot "${snapshotName}" created`);
}

// ✅ Ensure snapshot exists (idempotent)
async function ensureSnapshot(proxmoxID, vmName, snapshotName) {
  const exists = await snapshotExists(proxmoxID, snapshotName);
  if (exists) {
    console.log(`✅ Snapshot "${snapshotName}" already exists on ${vmName}`);
    return false;
  }
  await createSnapshot(proxmoxID, snapshotName);
  return true;
}

async function main() {
  const windowsType = Bun.argv[2];
  
  if (!windowsType || !WINDOWS_TEMPLATES[windowsType]) {
    console.log(`Usage: bun oneTimeSetup.js <windows-type>`);
    console.log(`Available: ${Object.keys(WINDOWS_TEMPLATES).join(", ")}`);
    process.exit(1);
  }

  console.log(`🚀 One-Time Setup: Kali + ${windowsType} + Snapshot\n`);

  // Check current VMs
  console.log("🔍 Checking current VMs...");
  const currentVMs = await getVMs();
  const kaliExists = currentVMs.some(vm => vm.name?.includes("attacker-kali"));
  const winExists = currentVMs.some(vm => vm.name === `${RANGE_ID}-${windowsType}`);
  
  console.log(kaliExists ? `✅ Kali exists` : `⏳ Kali will be created`);
  console.log(winExists ? `✅ ${windowsType} exists` : `⏳ ${windowsType} will be created`);

  // If Windows VM exists, just ensure snapshot
  if (winExists) {
    const winVM = currentVMs.find(vm => vm.name === `${RANGE_ID}-${windowsType}`);
    await ensureSnapshot(winVM.proxmoxID, winVM.name, BASE_SNAPSHOT_NAME);
    console.log("\n🎉 Setup complete! VM and snapshot ready.");
    console.log(`💡 For scenarios, run: bun scenario.js ${windowsType}`);
    return;
  }

  // Delete other Windows VMs to avoid conflicts
  console.log(`\n🧹 Cleaning up other Windows VMs...`);
  await deleteOtherWindowsVMs(windowsType);

  // Apply config
  console.log("\n📝 Applying configuration...");
  const yaml = generateYaml({ includeKali: !kaliExists, windowsType });
  await setRangeConfig(yaml);
  console.log("✅ Config applied");

  // Deploy
  console.log("\n🚀 Deploying (this takes a few minutes)...");
  await deployRange();
  console.log("✅ Deploy triggered");

  // Wait for READY state
  console.log("\n⏳ Waiting for deployment to complete...");
  let attempts = 0;
  while (attempts < 60) {
    await new Promise(r => setTimeout(r, 5000));
    const data = await apiCall("/range", "GET", { rangeID: RANGE_ID });
    const state = data?.rangeState || "unknown";
    console.log(`   📊 Status: ${state}`);
    if (state === "READY" || state === "SUCCESS") break;
    if (state === "ERROR") {
      console.error("❌ Deployment failed");
      console.error("💡 Check: ssh root@192.168.1.150 'ludus range errors'");
      process.exit(1);
    }
    attempts++;
  }

  // Get Proxmox ID of new Windows VM
  const vms = await getVMs();
  const winVM = vms.find(vm => vm.name === `${RANGE_ID}-${windowsType}`);
  if (!winVM) {
    console.error("❌ Windows VM not found after deploy");
    process.exit(1);
  }

  // Create snapshot via API
  await ensureSnapshot(winVM.proxmoxID, winVM.name, BASE_SNAPSHOT_NAME);

  console.log("\n🎉 One-time setup complete!");
  console.log(`   • Kali: ${kaliExists ? "preserved ✅" : "created 🆕"}`);
  console.log(`   • ${windowsType}: deployed + snapshotted ✅`);
  console.log(`\n💡 For scenarios, run: bun scenario.js ${windowsType}`);
  console.log(`💡 Reverting to "${BASE_SNAPSHOT_NAME}" will erase all session data`);
}

if (import.meta.main) {
  main().catch((err) => {
    console.error("\n❌ Fatal:", err.message);
    process.exit(1);
  });
}