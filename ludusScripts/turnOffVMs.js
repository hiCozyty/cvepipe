#!/usr/bin/env bun
//usage: bun run turnOffVms.js -> turn off all VMs except routers and attacker-kali
// usage: bun run turnOffVms.js [--vm <vm-name>] -> turn off specific VM
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
    const args = Bun.argv.slice(2);
    const vmFlagIndex = args.indexOf("--vm");
    const targetVM = vmFlagIndex !== -1 ? `${RANGE_ID}-${args[vmFlagIndex + 1]}` : null;
    console.log("🔍 Fetching VMs...");
    const data = await apiCall("/range", "GET", { rangeID: RANGE_ID });
    const allVMs = data?.VMs || [];

    let toOff;
    if (targetVM) {
        const vm = allVMs.find(v => v.name === targetVM);
        if (!vm) { console.error(`❌ VM "${targetVM}" not found`); process.exit(1); }
        if (!vm.poweredOn) { console.log(`✅ ${targetVM} is already off`); return; }
        toOff = [vm];
    } else {
        toOff = allVMs.filter(vm => !vm.isRouter && vm.poweredOn && !vm.name?.includes("attacker-kali"));
    }

    if (toOff.length === 0) { console.log("✅ No VMs are currently on"); return; }

    console.log(`\n⛔ Powering off ${toOff.length} VM(s):`);
    toOff.forEach(vm => console.log(`   • ${vm.name}`));
    await apiCall("/range/poweroff", "PUT", { rangeID: RANGE_ID }, { machines: toOff.map(vm => vm.name) });
    console.log("\n✅ Power off command sent");
}

main().catch(err => {
    console.error("\n❌ Fatal:", err.message);
    process.exit(1);
});