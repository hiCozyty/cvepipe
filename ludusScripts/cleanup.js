#!/usr/bin/env bun
//usage bun run cleanup.js <windows-type>
import { $ } from "bun";

const API_URL = process.env.LUDUS_API_URL;
const API_KEY = process.env.LUDUS_API_KEY?.trim();
const RANGE_ID = process.env.LUDUS_RANGE_ID || "ty";
const BASE_SNAPSHOT_NAME = "base-clean";

if (!API_KEY) {
    console.error("❌ Set LUDUS_API_KEY");
    process.exit(1);
}

async function apiCall(path, method = "GET", queryParams = {}, body = null, contentType = "application/json") {
    const qs = new URLSearchParams(queryParams).toString();
    const url = `${API_URL}${path}${qs ? `?${qs}` : ""}`;
    console.log(` → ${method} ${url}`);

    let result;
    if (body !== null) {
        const serialized = contentType === "application/json" ? JSON.stringify(body) : String(body);
        const escaped = serialized.replace(/'/g, "'\\''");
        result = await $`bash -c "curl -sk -X ${method} -H 'X-API-KEY: ${API_KEY}' -H 'Content-Type: ${contentType}' -d '${escaped}' '${url}'"`.text();
    } else {
        result = await $`curl -sk -X ${method} -H "X-API-KEY: ${API_KEY}" -H "Content-Type: ${contentType}" ${url}`.text();
    }

    console.log(` ← ${result.length} bytes`);
    if (!result.trim()) return null;
    try {
        return JSON.parse(result);
    } catch {
        return { _raw: result };
    }
}

async function getVMs() {
    const data = await apiCall("/range", "GET", { rangeID: RANGE_ID });
    return data?.VMs || [];
}

async function rollbackSnapshot(proxmoxID, snapshotName) {
    console.log(`⏪ Rolling back VM ${proxmoxID} to "${snapshotName}"...`);
    const result = await apiCall("/snapshots/rollback", "POST", { rangeID: RANGE_ID }, {
        vmids: [proxmoxID],
        name: snapshotName,
    });
    if (result?.errors?.length) throw new Error(`Rollback failed: ${result.errors[0].error}`);
    console.log(`✅ Rollback complete`);
}

async function powerOff(vmNames) {
    console.log(`⛔ Powering off: ${vmNames.join(", ")}`);
    await apiCall("/range/poweroff", "PUT", { rangeID: RANGE_ID }, { machines: vmNames });
}

async function waitForPower(vmName, desiredState = "off", timeoutSecs = 120) {
    console.log(`⏳ Waiting for ${vmName} to be ${desiredState}...`);
    for (let i = 0; i < timeoutSecs / 5; i++) {
        await new Promise(r => setTimeout(r, 5000));
        const vms = await getVMs();
        const vm = vms.find(v => v.name === vmName);
        const state = vm?.poweredOn ? "on" : "off";
        console.log(` 📊 ${vmName}: ${state}`);
        if (state === desiredState) return;
    }
    throw new Error(`Timeout waiting for ${vmName} to be ${desiredState}`);
}

async function main() {
    const windowsType = Bun.argv[2];

    if (!windowsType) {
        console.log(`Usage: bun run cleanup.js <windows-type>`);
        console.log(`Example: bun run cleanup.js win10`);
        process.exit(1);
    }

    const winVMName = `${RANGE_ID}-${windowsType}`;
    console.log(`🧹 Cleanup: ${windowsType}\n`);

    // Get current VMs
    console.log("🔍 Fetching VMs...");
    const vms = await getVMs();
    const winVM = vms.find(v => v.name === winVMName);

    if (!winVM) {
        console.error(`❌ VM "${winVMName}" not found`);
        process.exit(1);
    }

    // Verify base-clean snapshot exists
    console.log("\n🔎 Verifying base snapshot exists...");
    const snapData = await apiCall("/snapshots/list", "GET", { rangeID: RANGE_ID, vmids: winVM.proxmoxID });
    const hasSnapshot = snapData?.snapshots?.some(s => s.name === BASE_SNAPSHOT_NAME);
    if (!hasSnapshot) {
        console.error(`❌ Snapshot "${BASE_SNAPSHOT_NAME}" not found`);
        process.exit(1);
    }
    console.log(`✅ Snapshot "${BASE_SNAPSHOT_NAME}" found`);

    // Rollback to clean state (VM must be off for rollback)
    const currentState = winVM?.poweredOn ? "on" : "off";
    if (currentState === "on") {
        console.log("\n⏳ Waiting for VM to be off before rollback...");
        await powerOff([winVMName]);
        await waitForPower(winVMName, "off");
    }

    console.log("\n⏪ Reverting to clean snapshot...");
    await rollbackSnapshot(winVM.proxmoxID, BASE_SNAPSHOT_NAME);

    console.log(`\n✅ Cleanup complete! ${winVMName} reverted and powered off`);
}

if (import.meta.main) {
    main().catch((err) => {
        console.error("\n❌ Fatal:", err.message);
        process.exit(1);
    });
}