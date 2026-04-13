#!/usr/bin/env bun
// Usage: bun run reboot.js <windows-type>
// Example: bun run reboot.js win10-1607
import { $ } from "bun";

const API_URL = process.env.LUDUS_API_URL;
const API_KEY = process.env.LUDUS_API_KEY?.trim();
const RANGE_ID = process.env.LUDUS_RANGE_ID || "ty";

if (!API_KEY) {
    console.error("❌ Set LUDUS_API_KEY");
    process.exit(1);
}

async function apiCall(path, method = "GET", queryParams = {}, body = null) {
    const qs = new URLSearchParams(queryParams).toString();
    const url = `${API_URL}${path}${qs ? `?${qs}` : ""}`;
    console.log(` → ${method} ${url}`);

    let result;
    if (body !== null) {
        const serialized = JSON.stringify(body);
        const escaped = serialized.replace(/'/g, "'\\''");
        result = await $`bash -c "curl -sk -X ${method} -H 'X-API-KEY: ${API_KEY}' -H 'Content-Type: application/json' -d '${escaped}' '${url}'"`.text();
    } else {
        result = await $`curl -sk -X ${method} -H "X-API-KEY: ${API_KEY}" -H "Content-Type: application/json" ${url}`.text();
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

async function powerOff(vmNames) {
    console.log(`🔴 Powering off: ${vmNames.join(", ")}`);
    await apiCall("/range/poweroff", "PUT", { rangeID: RANGE_ID }, { machines: vmNames });
}

async function powerOn(vmNames) {
    console.log(`⚡ Powering on: ${vmNames.join(", ")}`);
    await apiCall("/range/poweron", "PUT", { rangeID: RANGE_ID }, { machines: vmNames });
}
async function waitForPower(vmName, desiredState = "on", timeoutSecs = 120) {
    console.log(`⏳ Waiting for ${vmName} to be ${desiredState}...`);
    for (let i = 0; i < timeoutSecs / 5; i++) {
        await new Promise(r => setTimeout(r, 5000));
        const vms = await getVMs();
        const vm = vms.find(v => v.name === vmName);
        const state = vm?.poweredOn ? "on" : "off";
        console.log(`   📊 ${vmName}: ${state}`);
        if (state === desiredState) return;
    }
    throw new Error(`Timeout waiting for ${vmName} to be ${desiredState}`);
}
export async function waitForIP(vmName, timeoutSecs = 120) {
    console.log(`⏳ Waiting for ${vmName} to get an IP...`);
    for (let i = 0; i < timeoutSecs / 5; i++) {
        const vms = await getVMs();
        const vm = vms.find(v => v.name === vmName);
        if (vm?.ip && vm.ip !== "null") {
            console.log(`✅ Got IP: ${vm.ip}`);
            return vm.ip;
        }
        console.log(`   ⏳ No IP yet... (${i * 5}s)`);
        await new Promise(r => setTimeout(r, 5000));
    }
    throw new Error(`Timeout waiting for IP on ${vmName}`);
}
export async function waitForWinRM(inventoryPath, vmName, targetIP, timeoutSecs = 120) {
    console.log(`⏳ Waiting for WinRM on ${vmName} (${targetIP})...`);
    
    // No need to parse inventory - we already have the IP!
    
    // Phase 1: Raw TCP port check
    const ports = [5985, 5986];
    let readyPort = null;
    console.log(`   🔍 Polling TCP ports...`);
    for (let i = 0; i < timeoutSecs / 2; i++) {
        for (const port of ports) {
            try {
                await $`bash -c "timeout 1 bash -c '</dev/tcp/${targetIP}/${port}' 2>/dev/null"`.quiet();
                readyPort = port;
                console.log(`   ✅ Port ${port} listening`);
                break;
            } catch {}
        }
        if (readyPort) break;
        await new Promise(r => setTimeout(r, 2000));
    }
    if (!readyPort) throw new Error(`Timeout: WinRM ports not open on ${targetIP}`);

    // Phase 2: ONE Ansible win_ping call
    console.log(`   🔄 Verifying WinRM session...`);
    try {
        await $`uv run ansible ${vmName} -i ${inventoryPath} -m win_ping -e "ansible_winrm_read_timeout_sec=10 ansible_winrm_operation_timeout_sec=5"`.quiet();
        console.log(`✅ WinRM ready on ${vmName} (port ${readyPort})`);
        return;
    } catch {
        throw new Error(`Port ${readyPort} open but WinRM not responding`);
    }
}

async function main() {
    const windowsType = Bun.argv[2];

    if (!windowsType) {
        console.log(`Usage: bun run reboot.js <windows-type>`);
        console.log(`Example: bun run reboot.js win10-1607`);
        process.exit(1);
    }

    const vmName = `${RANGE_ID}-${windowsType}`;
    console.log(`🔄 Rebooting ${vmName}...\n`);

    const vms = await getVMs();
    const vm = vms.find(v => v.name === vmName);
    if (!vm) {
        console.error(`❌ VM "${vmName}" not found`);
        process.exit(1);
    }

    await powerOff([vmName]);
    await waitForPower(vmName, "off");

    await powerOn([vmName]);
    await waitForPower(vmName, "on");
    const targetIP = await waitForIP(vmName);

    await waitForWinRM(`/tmp/ludus-inventory-${RANGE_ID}`, vmName, targetIP);

    console.log(`\n✅ ${vmName} is back up and WinRM is ready`);
}

main().catch((err) => {
    console.error("\n❌ Fatal:", err.message);
    process.exit(1);
});