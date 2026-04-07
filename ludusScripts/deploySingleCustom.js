#!/usr/bin/env bun
// usage: bun run deploySingleCustom.js <windows-type>

import { runOneTimeSetup } from "./oneTimeSetup.js";
import { WINDOWS_TEMPLATES } from "./const.js";
import { $ } from "bun";

const API_URL = process.env.LUDUS_API_URL;
const API_KEY = process.env.LUDUS_API_KEY?.trim();
const USER_API_KEY = process.env.LUDUS_USER_API_KEY?.trim() || API_KEY;
const RANGE_ID = process.env.LUDUS_RANGE_ID || "ty";

if (!API_KEY) { console.error("❌ Set LUDUS_API_KEY"); process.exit(1); }
if (!API_URL) { console.error("❌ Set LUDUS_API_URL"); process.exit(1); }

async function apiCall(path, method = "GET", queryParams = {}, body = null, contentType = "application/json", key = USER_API_KEY) {
  const qs = new URLSearchParams(queryParams).toString();
  const url = `${API_URL}${path}${qs ? `?${qs}` : ""}`;
  console.log(`   → ${method} ${url}`);

  let result;
  if (body !== null) {
    const serialized = contentType === "application/json" ? JSON.stringify(body) : String(body);
    const escaped = serialized.replace(/'/g, "'\\''");
    result = await $`bash -c "curl -sk -X ${method} -H 'X-API-KEY: ${key}' -H 'Content-Type: ${contentType}' -d '${escaped}' '${url}'"`.text();
  } else {
    result = await $`curl -sk -X ${method} -H "X-API-KEY: ${key}" ${url}`.text();
  }

  console.log(`   ← ${result.length} bytes`);
  if (!result.trim()) return null;
  try { return JSON.parse(result); } catch { return { _raw: result }; }
}

async function getVMs() {
  const data = await apiCall("/range", "GET", { rangeID: RANGE_ID });
  return data?.VMs || [];
}

function generateYaml(windowsType) {
  const win = WINDOWS_TEMPLATES[windowsType];
  return `ludus:
  - vm_name: "{{ range_id }}-attacker-kali"
    hostname: attacker-kali
    template: kali-x64-desktop-template
    vlan: 99
    ip_last_octet: 1
    ram_gb: 4
    cpus: 2
    linux: true

  - vm_name: "{{ range_id }}-${windowsType}"
    hostname: ${win.hostname}
    template: ${win.template}
    vlan: 99
    ip_last_octet: ${win.ip_last_octet}
    ram_gb: 4
    cpus: 2
    windows:
      sysprep: false
`;
}

async function setRangeConfig(yaml) {
  console.log("📝 Setting range config...");

  const qs = new URLSearchParams({ rangeID: RANGE_ID }).toString();
  const url = `${API_URL}/range/config?${qs}`;

  const formData = new FormData();
  formData.append("file", new Blob([yaml], { type: "application/yaml" }), "range.yml");
  formData.append("force", "false");

  // Bun-specific: disable TLS verification for self-signed cert
  const response = await fetch(url, {
    method: "PUT",
    headers: { "X-API-KEY": USER_API_KEY },
    body: formData,
    tls: { rejectUnauthorized: false },
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Config update failed (${response.status}): ${text}`);
  }

  console.log("✅ Config applied");
}

async function powerOffVMs(vmNames) {
  if (vmNames.length === 0) return;
  console.log(`⛔ Powering off: ${vmNames.join(", ")}`);
  await apiCall("/range/poweroff", "PUT", { rangeID: RANGE_ID }, { machines: vmNames });
  console.log("✅ Power off command sent");
}

async function waitForAllOff(vmNames, timeoutSecs = 120) {
  console.log(`⏳ Waiting for VMs to power off...`);
  for (let i = 0; i < timeoutSecs / 5; i++) {
    await new Promise(r => setTimeout(r, 5000));
    const vms = await getVMs();
    const stillOn = vmNames.filter(name => {
      const vm = vms.find(v => v.name === name);
      return vm?.poweredOn === true;
    });
    console.log(`   📊 Still on: ${stillOn.length > 0 ? stillOn.join(", ") : "none"}`);
    if (stillOn.length === 0) return;
  }
  console.warn("⚠️  Timeout waiting for VMs to power off, continuing anyway...");
}

async function waitForDeploy(timeoutSecs = 600) {
  console.log("\n⏳ Waiting for deployment to complete...");

  const startTime = Date.now();

  while (Date.now() - startTime < timeoutSecs * 1000) {
    await new Promise(resolve => setTimeout(resolve, 5000));

    const data = await apiCall("/range", "GET", { rangeID: RANGE_ID });
    const state = data?.rangeState || "unknown";
    const elapsed = Math.round((Date.now() - startTime) / 1000);

    console.log(`   📊 Status: ${state} (${elapsed}s)`);

    if (state === "SUCCESS" || state === "READY") {
      console.log("✅ Deployment complete!");
      return;
    }

    if (state === "ERROR") {
      console.error("❌ Deployment entered ERROR state");
      const errors = await apiCall("/range/errors", "GET", { rangeID: RANGE_ID });
      console.error("📋 Debug info:", errors?._raw || JSON.stringify(errors));
      throw new Error("Deployment failed with ERROR state");
    }
  }

  throw new Error(`Deployment timed out after ${timeoutSecs}s`);
}

async function main() {
  const windowsType = Bun.argv[2];

  if (!windowsType || !WINDOWS_TEMPLATES[windowsType]) {
    console.log(`Usage: bun deploy.js <windows-type>`);
    console.log(`Available: ${Object.keys(WINDOWS_TEMPLATES).join(", ")}`);
    process.exit(1);
  }

  const winVMName = `${RANGE_ID}-${windowsType}`;
  const kaliVMName = `${RANGE_ID}-attacker-kali`;
  const targetVMNames = [kaliVMName, winVMName];

  console.log(`🚀 Deploy: Kali + ${windowsType}`);
  console.log(`📋 Target VMs: ${targetVMNames.join(", ")}\n`);

  // Check current state
  console.log("🔍 Checking current VMs...");
  const allVMs = await getVMs();
  const winVM = allVMs.find(v => v.name === winVMName);
  const kaliVM = allVMs.find(v => v.name === kaliVMName);

  // Power off anything that's on but not in our target set
  const vmsToOff = allVMs.filter(vm => {
    if (vm.isRouter) return false;
    if (!vm.poweredOn) return false;
    if (targetVMNames.includes(vm.name)) return false;
    return true;
  }).map(vm => vm.name);

  if (vmsToOff.length > 0) {
    console.log(`\n⛔ Powering off ${vmsToOff.length} unneeded VM(s)...`);
    await powerOffVMs(vmsToOff);
    await waitForAllOff(vmsToOff);
  } else {
    console.log("✅ No unneeded VMs are powered on");
  }

  if (winVM) {
    console.log(`\n✅ ${winVMName} already exists, skipping deploy`);

    const toTurnOn = [];
    if (!winVM.poweredOn) toTurnOn.push(winVMName);
    if (kaliVM && !kaliVM.poweredOn) toTurnOn.push(kaliVMName);

    if (toTurnOn.length > 0) {
      console.log(`\n⚡ Powering on: ${toTurnOn.join(", ")}`);
      await apiCall("/range/poweron", "PUT", { rangeID: RANGE_ID }, { machines: toTurnOn });
      console.log("✅ Power on command sent");
    } else {
      console.log("✅ VMs are already on");
    }
  }else {
    // VM doesn't exist — set config and deploy
    console.log(`\n⏳ ${winVMName} not found, deploying from template...`);

    const yaml = generateYaml(windowsType);
    console.log("📄 Generated config:\n" + yaml);
    await setRangeConfig(yaml);

    console.log("\n🚀 Deploying...");
    await apiCall("/range/deploy", "POST", { rangeID: RANGE_ID }, {});

    await waitForDeploy();
    await runOneTimeSetup(windowsType);
  }

  console.log(`\n🎉 Done! Kali + ${windowsType} are ready`);
  console.log(`💡 Next: bun oneTimeSetup.js ${windowsType}`);
  console.log(`💡 Then: bun scenario.js ${windowsType} <playbook>`);
}

if (import.meta.main) {
  main().catch(err => {
    console.error("\n❌ Fatal:", err.message);
    process.exit(1);
  });
}