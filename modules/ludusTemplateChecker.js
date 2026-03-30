#!/usr/bin/env bun
/**
 * Ludus Template Checker & Creator
 * 
 * Reads filtered_modules.json and creates Ludus templates ONLY for OS versions actually needed
 */

import { $ } from 'bun';

// ============================================================================
// Configuration (from .env)
// ============================================================================
const LUDUS_API_URL = process.env.LUDUS_API_URL;
const LUDUS_API_KEY = process.env.LUDUS_API_KEY;
const FILTERED_MODULES_PATH = './output/filtered_modules.json';
const TEMPLATES_OUTPUT_DIR = './ludus-templates';
const MAPPING_OUTPUT_PATH = './output/cve_template_mapping.json';

// ============================================================================
// Ludus API Client
// ============================================================================
async function ludusRequest(endpoint, method = 'GET', body = null) {
    if (!LUDUS_API_KEY) {
        throw new Error('LUDUS_API_KEY environment variable is not set');
    }
    
    const url = `${LUDUS_API_URL}${endpoint}`;
    const headers = {
        'Authorization': `Bearer ${LUDUS_API_KEY}`,
        'Content-Type': 'application/json'
    };
    
    const options = { method, headers };
    if (body) options.body = JSON.stringify(body);
    
    const response = await fetch(url, options);
    
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Ludus API ${method} ${endpoint} failed: ${response.status} - ${errorText}`);
    }
    
    if (response.status === 204) return null;
    return await response.json();
}

async function getExistingTemplates() {
    console.log('[LUDUS] Fetching existing templates...');
    const templates = await ludusRequest('/templates');
    console.log(`[LUDUS] Found ${templates?.length || 0} existing templates`);
    return templates || [];
}

async function createLudusTemplate(templateData) {
    console.log(`[LUDUS] Creating template: ${templateData.name}`);
    const result = await ludusRequest('/templates', 'POST', templateData);
    console.log(`[LUDUS] Template created with ID: ${result?.id}`);
    return result;
}

// ============================================================================
// Helper Functions
// ============================================================================
function extractWindowsVersion(targets) {
    if (!targets?.length) return 'windows-generic';
    
    const targetStr = targets.join(' ').toLowerCase();
    
    if (targetStr.includes('2000')) return 'windows-2000';
    if (targetStr.includes('xp')) return 'windows-xp';
    if (targetStr.includes('2003')) return 'windows-2003';
    if (targetStr.includes('vista')) return 'windows-vista';
    if (targetStr.includes('2008')) return 'windows-2008';
    if (targetStr.includes('win7') || targetStr.includes('windows 7')) return 'windows-7';
    if (targetStr.includes('2012')) return 'windows-2012';
    if (targetStr.includes('win8') || targetStr.includes('windows 8')) return 'windows-8';
    if (targetStr.includes('2016')) return 'windows-2016';
    if (targetStr.includes('win10') || targetStr.includes('windows 10')) return 'windows-10';
    if (targetStr.includes('2019')) return 'windows-2019';
    if (targetStr.includes('win11') || targetStr.includes('windows 11')) return 'windows-11';
    if (targetStr.includes('2022')) return 'windows-2022';
    
    return 'windows-generic';
}

function generateTemplateName(osVersion) {
    return `${osVersion}-generic`;
}

function generateLudusTemplate(osVersion) {
    const templateName = generateTemplateName(osVersion);
    
    return {
        name: templateName,
        description: `Universal ${osVersion} template for CVE lab provisioning`,
        os: 'windows',
        os_version: osVersion,
        network: {
            ports: [],
            firewall: 'default'
        },
        ansible: {
            playbook: null
        },
        metadata: {
            source: 'cvepipe-phase2',
            universal: true,
            created_at: new Date().toISOString()
        }
    };
}

// ============================================================================
// Main Logic
// ============================================================================
async function loadFilteredModules() {
    console.log(`[LOAD] Loading filtered modules from ${FILTERED_MODULES_PATH}...`);
    
    const fileExists = await $`test -f ${FILTERED_MODULES_PATH}`.quiet()
        .then(() => true)
        .catch(() => false);
    
    if (!fileExists) {
        throw new Error(`Filtered modules file not found: ${FILTERED_MODULES_PATH}`);
    }
    
    const content = await Bun.file(FILTERED_MODULES_PATH).text();
    const modules = JSON.parse(content);
    console.log(`[LOAD] Loaded ${modules.length} modules`);
    
    return modules;
}

function getRequiredOSVersions(modules) {
    const osVersions = new Set();
    
    for (const module of modules) {
        const osVersion = extractWindowsVersion(module.targets);
        osVersions.add(osVersion);
    }
    
    return Array.from(osVersions);
}

async function main() {
    console.log('Ludus Template Checker & Creator');
    console.log('=================================\n');
    
    if (!LUDUS_API_URL) {
        throw new Error('LUDUS_API_URL environment variable is not set');
    }
    
    // 1. Load filtered modules
    const allModules = await loadFilteredModules();
    
    // 2. Get unique OS versions actually needed
    const requiredOSVersions = getRequiredOSVersions(allModules);
    console.log(`[OS] Unique Windows versions needed: ${requiredOSVersions.length}\n`);
    console.log('Required OS versions:');
    for (const os of requiredOSVersions.sort()) {
        console.log(`  - ${os}`);
    }
    console.log();
    
    // 3. Get existing Ludus templates
    const existingTemplates = await getExistingTemplates();
    const existingNames = new Set(existingTemplates.map(t => t.name));
    
    // 4. Create templates ONLY for OS versions we need
    await $`mkdir -p ${TEMPLATES_OUTPUT_DIR}`;
    
    let created = 0;
    let skipped = 0;
    let errors = 0;
    
    console.log('[PROCESS] Checking and creating templates...\n');
    
    for (const osVersion of requiredOSVersions) {
        const templateName = generateTemplateName(osVersion);
        
        if (existingNames.has(templateName)) {
            console.log(`[SKIP] Template already exists: ${templateName}`);
            skipped++;
            continue;
        }
        
        try {
            const templateData = generateLudusTemplate(osVersion);
            await createLudusTemplate(templateData);
            
            const localPath = `${TEMPLATES_OUTPUT_DIR}/${templateName}.json`;
            await Bun.write(localPath, JSON.stringify(templateData, null, 2));
            
            console.log(`[CREATE] Created template: ${templateName}`);
            created++;
        } catch (error) {
            console.error(`[ERROR] Failed to create template ${templateName}: ${error.message}`);
            errors++;
        }
    }
    
    // 5. Build CVE-to-Template mapping for scenario builder
    console.log('\n[MAP] Building CVE-to-template mapping...\n');
    
    const cveMapping = {
        generated_at: new Date().toISOString(),
        total_cves: allModules.length,
        templates_required: requiredOSVersions.length,
        templates_created: created,
        templates_skipped: skipped,
        cves: []
    };
    
    for (const module of allModules) {
        const osVersion = extractWindowsVersion(module.targets);
        const templateName = generateTemplateName(osVersion);
        
        cveMapping.cves.push({
            msf_path: module.msf_path,
            name: module.name,
            cves: module.cves || [],
            service_category: module.service_category,
            access_type: module.access_type,
            provisioning_complexity: module.provisioning_complexity || 'standard',
            template: templateName,
            os_version: osVersion
        });
    }
    
    // 6. Save mapping file
    await Bun.write(MAPPING_OUTPUT_PATH, JSON.stringify(cveMapping, null, 2));
    console.log(`[OUTPUT] Written: ${MAPPING_OUTPUT_PATH}`);
    
    // 7. Summary
    console.log('\n' + '='.repeat(60));
    console.log('TEMPLATE CREATION SUMMARY');
    console.log('='.repeat(60));
    console.log(`Total CVEs to support: ${allModules.length}`);
    console.log(`Unique OS versions needed: ${requiredOSVersions.length}`);
    console.log(`Templates created: ${created}`);
    console.log(`Templates skipped (already exist): ${skipped}`);
    console.log(`Errors: ${errors}`);
    console.log('='.repeat(60));
    console.log('\n[INFO] Local template backups saved to: ./ludus-templates/');
    console.log('[INFO] CVE-to-template mapping saved to: ./output/cve_template_mapping.json');
    console.log('[NEXT] Scenario builder will use mapping to chain template + ansible playbook\n');
}

main().catch(console.error);

export {
    extractWindowsVersion,
    generateTemplateName,
    generateLudusTemplate,
    ludusRequest,
    getExistingTemplates,
    createLudusTemplate
};