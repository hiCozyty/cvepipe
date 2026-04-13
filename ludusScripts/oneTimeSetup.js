#!/usr/bin/env bun
// usage bun run oneTimeSetup.js <windows-type>

import { $ } from "bun";
import { WINDOWS_TEMPLATES } from "./const";
import {getAnsibleInventory, waitForIP,waitForWinRM} from "./scenario.js";

const API_URL = process.env.LUDUS_API_URL
const API_KEY = process.env.LUDUS_API_KEY?.trim();
const RANGE_ID = process.env.LUDUS_RANGE_ID || "ty";
const BASE_SNAPSHOT_NAME = "base-clean";

if (!API_KEY) { console.error("❌ Set LUDUS_API_KEY"); process.exit(1); }

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
  try { return JSON.parse(result); } catch { return { _raw: result }; }
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

async function snapshotExists(proxmoxID, snapshotName) {
  try {
    const data = await apiCall("/snapshots/list", "GET", { rangeID: RANGE_ID, vmids: proxmoxID });
    const snapshots = data?.snapshots || data || [];
    return snapshots.some(s => s.name === snapshotName || s.snapname === snapshotName);
  } catch {
    return false;
  }
}

async function createSnapshot(proxmoxID, snapshotName) {
  console.log(`📸 Creating snapshot "${snapshotName}" on VM ${proxmoxID}...`);
  const body = {
    vmids: [proxmoxID],
    name: snapshotName,
    description: `Base clean state for ${RANGE_ID}-${snapshotName}`,
    includeRAM: true,
  };
  const result = await apiCall("/snapshots/create", "POST", { rangeID: RANGE_ID }, body, "application/json");
  if (result?.errors?.length) {
    throw new Error(`Snapshot failed on VM ${proxmoxID}: ${result.errors[0].error}`);
  }
  console.log(`✅ Snapshot "${snapshotName}" created`);
}

async function ensureSnapshot(proxmoxID, vmName, snapshotName) {
  const exists = await snapshotExists(proxmoxID, snapshotName);
  if (exists) {
    console.log(`✅ Snapshot "${snapshotName}" already exists on ${vmName}`);
    return false;
  }
  await createSnapshot(proxmoxID, snapshotName);
  return true;
}

export async function runOneTimeSetup(windowsType) {
  if (!windowsType || !WINDOWS_TEMPLATES[windowsType]) {
    throw new Error(`Unknown windows type: ${windowsType}. Available: ${Object.keys(WINDOWS_TEMPLATES).join(", ")}`);
  }

  console.log(`🚀 One-Time Setup: Kali + ${windowsType} + Snapshot\n`);

  console.log("🔍 Checking current VMs...");
  const currentVMs = await getVMs();
  const winVM = currentVMs.find(vm => vm.name === `${RANGE_ID}-${windowsType}`);

  if (winVM) {
    await waitForIP(winVM.name);  // add
    const inventoryPath = `/tmp/ludus-inventory-${RANGE_ID}`;
    const inventoryText = await getAnsibleInventory();
    await Bun.write(inventoryPath, inventoryText);
    await waitForWinRM(inventoryPath, winVM.name, winVM.ip);  // add
    await ensureSnapshot(winVM.proxmoxID, winVM.name, BASE_SNAPSHOT_NAME);
    console.log("\n🎉 Setup complete! VM and snapshot ready.");
    return;
  }

  console.log(`\n🧹 Cleaning up other Windows VMs...`);
  await deleteOtherWindowsVMs(windowsType);

  // Wait for READY state
  console.log("\n⏳ Waiting for deployment to complete...");
  let attempts = 0;
  while (attempts < 60) {
    await new Promise(r => setTimeout(r, 5000));
    const data = await apiCall("/range", "GET", { rangeID: RANGE_ID });
    const state = data?.rangeState || "unknown";
    console.log(`   📊 Status: ${state}`);
    if (state === "READY" || state === "SUCCESS") break;
    if (state === "ERROR") throw new Error("Deployment failed with ERROR state");
    attempts++;
  }

  const vms = await getVMs();
  const newWinVM = vms.find(vm => vm.name === `${RANGE_ID}-${windowsType}`);
  if (!newWinVM) throw new Error("Windows VM not found after deploy");

  await waitForIP(newWinVM.name);  // add
  const inventoryPath = `/tmp/ludus-inventory-${RANGE_ID}`;
  const inventoryText = await getAnsibleInventory();
  await Bun.write(inventoryPath, inventoryText);
  await waitForWinRM(inventoryPath, newWinVM.name, newWinVM.ip);  // add

  await ensureSnapshot(newWinVM.proxmoxID, newWinVM.name, BASE_SNAPSHOT_NAME);
  console.log("\n🎉 One-time setup complete!");
  console.log(`   • ${windowsType}: snapshotted ✅`);
}

if (import.meta.main) {
  const windowsType = Bun.argv[2];
  if (!windowsType || !WINDOWS_TEMPLATES[windowsType]) {
    console.log(`Usage: bun oneTimeSetup.js <windows-type>`);
    console.log(`Available: ${Object.keys(WINDOWS_TEMPLATES).join(", ")}`);
    process.exit(1);
  }
  runOneTimeSetup(windowsType).catch(err => {
    console.error("\n❌ Fatal:", err.message);
    process.exit(1);
  });
}