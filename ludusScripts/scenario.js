#!/usr/bin/env bun
//usage bun run scenario.js <windows-type> <ansible-playbook> --no-revert (optional flag)
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

async function powerOn(vmNames) {
    console.log(`⚡ Powering on: ${vmNames.join(", ")}`);
    await apiCall("/range/poweron", "PUT", { rangeID: RANGE_ID }, { machines: vmNames });
}

async function getAnsibleInventory() {
    const qs = new URLSearchParams({ rangeID: RANGE_ID }).toString();
    const url = `${API_URL}/range/ansibleinventory?${qs}`;
    console.log(` → GET ${url}`);
    const result = await $`curl -sk -X GET -H "X-API-KEY: ${API_KEY}" "${url}"`.text();
    console.log(` ← ${result.length} bytes`);
    const parsed = JSON.parse(result);
    if (!parsed?.result) throw new Error("No inventory data in response");
    return parsed.result;
}

async function waitForPower(vmName, desiredState = "on", timeoutSecs = 120) {
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
async function waitForWinRM(inventoryPath, vmName, timeoutSecs = 120) {
    console.log(`⏳ Waiting for WinRM on ${vmName}...`);
    for (let i = 0; i < timeoutSecs / 5; i++) {
        try {
            await $`uv run ansible ${vmName} -i ${inventoryPath} -m win_ping -e "ansible_winrm_read_timeout_sec=10 ansible_winrm_operation_timeout_sec=5"`.quiet();            
            console.log(`✅ WinRM ready on ${vmName}`);
            return;
        } catch {
            console.log(`   ⏳ WinRM not ready... (${i * 5}s)`);
            await new Promise(r => setTimeout(r, 5000));
        }
    }
    throw new Error(`Timeout waiting for WinRM on ${vmName}`);
}
async function main() {
    const args = Bun.argv.slice(2);
    const noRevert = args.includes("--no-revert");
    const positional = args.filter(a => !a.startsWith("--"));

    const windowsType = Bun.argv[2];
    const ansibleScript = Bun.argv[3];

    if (!windowsType || !ansibleScript) {
        console.log(`Usage: bun scenario.js <windows-type> <ansible-playbook> [--no-revert]`);
        console.log(`Example: bun scenario.js win10 playbooks/cve-2021-34527.yml`);
        console.log(`         bun scenario.js win10 playbooks/cve-2021-34527.yml --no-revert`);
        process.exit(1);
    }

    const winVMName = `${RANGE_ID}-${windowsType}`;
    console.log(`🎯 Scenario: ${windowsType} → ${ansibleScript}\n`);

    // Get current VMs
    console.log("🔍 Fetching VMs...");
    const vms = await getVMs();
    const winVM = vms.find(v => v.name === winVMName);
    const kaliVM = vms.find(v => v.name?.includes("attacker-kali"));

    if (!winVM) {
        console.error(`❌ VM "${winVMName}" not found. Run: bun oneTimeSetup.js ${windowsType}`);
        process.exit(1);
    }
    if (!kaliVM) {
        console.error(`❌ Kali not found. Run: bun oneTimeSetup.js ${windowsType}`);
        process.exit(1);
    }

    // Verify base-clean snapshot exists
    console.log("\n🔎 Verifying base snapshot exists...");
    const snapData = await apiCall("/snapshots/list", "GET", { rangeID: RANGE_ID, vmids: winVM.proxmoxID });
    const hasSnapshot = snapData?.snapshots?.some(s => s.name === BASE_SNAPSHOT_NAME);
    if (!hasSnapshot) {
        console.error(`❌ Snapshot "${BASE_SNAPSHOT_NAME}" not found. Run: bun oneTimeSetup.js ${windowsType}`);
        process.exit(1);
    }
    console.log(`✅ Snapshot "${BASE_SNAPSHOT_NAME}" found`);

    if (noRevert) {
        console.log("\n⏭️  Skipping snapshot revert (--no-revert)");
    } else {
        // Rollback Windows VM to clean state (VM must be off for rollback)
        console.log("\n⏪ Reverting to clean snapshot...");
        await rollbackSnapshot(winVM.proxmoxID, BASE_SNAPSHOT_NAME);
    }
    // Power on Kali if needed
    const kaliPower = kaliVM?.poweredOn ? "on" : "off";
    if (kaliPower !== "on") {
        console.log("\n🐉 Powering on Kali...");
        await powerOn([kaliVM.name]);
    } else {
        console.log(`\n✅ Kali already on`);
    }

    // Power on Windows VM
    console.log(`\n🪟 Powering on ${winVMName}...`);
    await powerOn([winVMName]);
    await waitForPower(winVMName, "on");

    // wait for winRM to be ready
    await waitForWinRM(`/tmp/ludus-inventory-${RANGE_ID}`, winVMName);

    // Check if ansible-playbook is available
    try {
        await $`uv run ansible-playbook --version`.quiet();
    } catch {
        console.error("❌ ansible-playbook not found via uv");
        console.error("💡 Run: uv add ansible pywinrm && uv sync");
        process.exit(1);
    }

    // Fetch Ludus inventory (contains all VM hostnames/IPs/groups)
    console.log("\n📋 Fetching Ludus inventory...");
    const inventoryText = await getAnsibleInventory();

    // Write inventory to temp file
    const inventoryPath = `/tmp/ludus-inventory-${RANGE_ID}`;
    await Bun.write(inventoryPath, inventoryText);
    console.log(`📄 Inventory written to ${inventoryPath}`);

    // Run Ansible with Ludus inventory, limited to the target Windows VM only
    console.log(`\n🔧 Running Ansible: ${ansibleScript} (target: ${winVMName})`);
    console.log("─".repeat(50));

    try {
        await $`uv run ansible-playbook -i ${inventoryPath} --limit ${winVMName} ${ansibleScript}`;
        console.log("─".repeat(50));
        console.log(`\n✅ Scenario complete!`);
    } catch (err) {
        console.log("─".repeat(50));
        console.error(`\n❌ Ansible failed (exit ${err.exitCode})`);
        console.error(`💡 Check playbook syntax and target host connectivity`);
        process.exit(err.exitCode ?? 1);
    }
}

if (import.meta.main) {
    main().catch((err) => {
        console.error("\n❌ Fatal:", err.message);
        process.exit(1);
    });
}