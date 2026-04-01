#!/usr/bin/env bun

import { $ } from "bun";

const API_URL = process.env.LUDUS_API_URL;
const API_KEY = process.env.LUDUS_API_KEY?.trim();
const RANGE_ID = process.env.LUDUS_RANGE_ID || "ty";

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

async function main() {
  console.log(`🧹 Cleanup: powering off Windows VMs (Kali untouched)\n`);

  console.log("🔍 Fetching VMs...");
  const data = await apiCall("/range", "GET", { rangeID: RANGE_ID });
  const vms = data?.VMs || [];

  const toOff = vms.filter(vm => {
    if (vm.name?.includes("attacker-kali")) return false;  // leave Kali alone
    if (vm.isRouter === true) return false;                 // leave router alone
    const state = vm?.powerState?.toLowerCase() || vm?.power?.toLowerCase();
    return state === "on" || state === "running";
  });

  if (toOff.length === 0) {
    console.log("✅ No Windows VMs are currently on. Nothing to do.");
    return;
  }

  console.log(`\n🔌 Powering off ${toOff.length} VM(s):`);
  for (const vm of toOff) console.log(`   • ${vm.name}`);

  await apiCall("/range/poweroff", "PUT", { rangeID: RANGE_ID }, {
    machines: toOff.map(vm => vm.name),
  });

  console.log(`\n✅ Cleanup complete. Kali and router left running.`);
}

if (import.meta.main) {
  main().catch((err) => {
    console.error("\n❌ Fatal:", err.message);
    process.exit(1);
  });
}