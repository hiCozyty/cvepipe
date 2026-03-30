#!/usr/bin/env bun
/**
 * Ludus Template Compatibility Checker
 * 
 * Tests filtered_modules.json against available Ludus templates
 * Reports modules with unsupported OS versions
 */

import { describe, it, expect , beforeAll, afterAll} from 'bun:test';
import { $ } from 'bun';

// ============================================================================
// Configuration
// ============================================================================
const FILTERED_MODULES_PATH = './output/filtered_modules.json';
const LUDUS_TEMPLATES = [
    'debian10',
    'rocky-9-x64-server',
    'ubuntu-20.04-x64-server',
    'ubuntu-22.04-x64-server',
    'win10-21h1-x64-enterprise',
    'win11-23h2-x64-enterprise',
    'win2012r2-server-x64',
    'win2016-server-x64',
    'win2019-server-x64',
    'commando-vm',      // requires ansible role: badsectorlabs.ludus_commandovm
    'flare-vm',         // requires ansible role: badsectorlabs.ludus_flarevm
    'remnux'            // requires ansible role: badsectorlabs.ludus_remnux
];

// Windows template mapping (extracted version → Ludus template)
const WINDOWS_TEMPLATE_MAP = {
    'windows-2000': null,
    'windows-xp': null,
    'windows-2003': null,
    'windows-vista': null,
    'windows-2008': null,
    'windows-7': null,
    'windows-8': null,
    'windows-2012': 'win2012r2-server-x64',
    'windows-2016': 'win2016-server-x64',
    'windows-2019': 'win2019-server-x64',
    'windows-10': 'win10-21h1-x64-enterprise',
    'windows-11': 'win11-23h2-x64-enterprise',
    'windows-generic': 'win10-21h1-x64-enterprise'
};

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
    if (targetStr.includes('2022')) return 'windows-2019';
    
    return 'windows-generic';
}

function getLudusTemplate(osVersion) {
    return WINDOWS_TEMPLATE_MAP[osVersion] || null;
}

function isTemplateSupported(templateName) {
    if (!templateName) return false;
    return LUDUS_TEMPLATES.includes(templateName);
}

function getSpecialRequirements(templateName) {
    const requirements = {
        'commando-vm': 'badsectorlabs.ludus_commandovm',
        'flare-vm': 'badsectorlabs.ludus_flarevm',
        'remnux': 'badsectorlabs.ludus_remnux'
    };
    return requirements[templateName] || null;
}

// ============================================================================
// Tests
// ============================================================================
describe('Ludus Template Compatibility Checker', () => {
    // ✅ Declare variables in outer scope so all hooks can access them
    let modules = [];
    let unsupportedModules = [];
    let supportedModules = [];
    let specialRequirementModules = [];

    beforeAll(async () => {
        // Load filtered modules
        const fileExists = await $`test -f ${FILTERED_MODULES_PATH}`.quiet()
            .then(() => true)
            .catch(() => false);
        
        expect(fileExists).toBeTrue();
        
        const content = await Bun.file(FILTERED_MODULES_PATH).text();
        modules = JSON.parse(content);
        
        // Categorize modules
        unsupportedModules = [];
        supportedModules = [];
        specialRequirementModules = [];
        
        for (const module of modules) {
            const osVersion = extractWindowsVersion(module.targets);
            const template = getLudusTemplate(osVersion);
            const supported = isTemplateSupported(template);
            const specialReq = getSpecialRequirements(template);
            
            const moduleInfo = {
                msf_path: module.msf_path,
                name: module.name,
                extracted_os: osVersion,
                ludus_template: template,
                cves: module.cves || [],
                access_type: module.access_type,
                provisioning_complexity: module.provisioning_complexity
            };
            
            if (!supported) {
                unsupportedModules.push(moduleInfo);
            } else {
                supportedModules.push(moduleInfo);
                if (specialReq) {
                    specialRequirementModules.push({
                        ...moduleInfo,
                        ansible_role: specialReq
                    });
                }
            }
        }
    });

    describe('Template Coverage', () => {
        it('should report total modules analyzed', () => {
            console.log(`\n📊 Total modules analyzed: ${modules.length}`);
            expect(modules.length).toBeGreaterThan(0);
        });

        it('should report supported modules count', () => {
            console.log(`✅ Supported modules: ${supportedModules.length} (${((supportedModules.length / modules.length) * 100).toFixed(1)}%)`);
        });

        it('should report unsupported modules count', () => {
            console.log(`❌ Unsupported modules: ${unsupportedModules.length} (${((unsupportedModules.length / modules.length) * 100).toFixed(1)}%)`);
        });

        it('should report special requirement modules count', () => {
            console.log(`⚠️  Special requirements (Ansible roles): ${specialRequirementModules.length}`);
        });
    });

    describe('Unsupported OS Versions', () => {
        it('should list all unsupported modules', () => {
            if (unsupportedModules.length > 0) {
                console.log('\n❌ UNSUPPORTED MODULES (No Ludus template available):\n');
                console.log(JSON.stringify(unsupportedModules, null, 2));
                
                // Group by OS version for better visibility
                const byOS = {};
                for (const mod of unsupportedModules) {
                    const os = mod.extracted_os;
                    if (!byOS[os]) byOS[os] = [];
                    byOS[os].push(mod.msf_path);
                }
                
                console.log('\n📁 Unsupported modules by OS version:');
                for (const [os, paths] of Object.entries(byOS)) {
                    console.log(`\n  ${os}: ${paths.length} modules`);
                    console.log(`    Examples: ${paths.slice(0, 5).join(', ')}${paths.length > 5 ? '...' : ''}`);
                }
            }
        });

        it('should identify missing Windows templates', () => {
            const missingTemplates = new Set(unsupportedModules.map(m => m.extracted_os));
            console.log('\n🔍 Missing Ludus templates for these Windows versions:');
            for (const os of missingTemplates) {
                console.log(`  - ${os}`);
            }
            expect(missingTemplates.size).toBeLessThan(10);
        });
    });

    describe('Special Requirements', () => {
        it('should list modules requiring special Ansible roles', () => {
            if (specialRequirementModules.length > 0) {
                console.log('\n⚠️  MODULES REQUIRING SPECIAL ANSIBLE ROLES:\n');
                
                const byRole = {};
                for (const mod of specialRequirementModules) {
                    const role = mod.ansible_role;
                    if (!byRole[role]) byRole[role] = [];
                    byRole[role].push(mod);
                }
                
                for (const [role, mods] of Object.entries(byRole)) {
                    console.log(`\n  Ansible Role: ${role}`);
                    console.log(`  Modules: ${mods.length}`);
                    console.log(`  Examples: ${mods.slice(0, 3).map(m => m.msf_path).join(', ')}${mods.length > 3 ? '...' : ''}`);
                }
            }
        });
    });

    describe('Template Distribution', () => {
        it('should show template usage distribution', () => {
            const templateUsage = {};
            
            for (const mod of supportedModules) {
                const template = mod.ludus_template;
                if (!templateUsage[template]) templateUsage[template] = 0;
                templateUsage[template]++;
            }
            
            console.log('\n📊 LUDUS TEMPLATE USAGE DISTRIBUTION:\n');
            const sorted = Object.entries(templateUsage).sort((a, b) => b[1] - a[1]);
            
            for (const [template, count] of sorted) {
                const specialReq = getSpecialRequirements(template);
                const reqMarker = specialReq ? ' ⚠️' : ' ✅';
                console.log(`  ${template}${reqMarker}: ${count} modules (${((count / supportedModules.length) * 100).toFixed(1)}%)`);
            }
        });
    });

    describe('Access Type Distribution', () => {
        it('should show access type breakdown for supported modules', () => {
            const byAccessType = {};
            
            for (const mod of supportedModules) {
                const type = mod.access_type || 'unknown';
                if (!byAccessType[type]) byAccessType[type] = 0;
                byAccessType[type]++;
            }
            
            console.log('\n🎯 ACCESS TYPE DISTRIBUTION (Supported Modules Only):\n');
            for (const [type, count] of Object.entries(byAccessType).sort((a, b) => b[1] - a[1])) {
                console.log(`  ${type}: ${count}`);
            }
        });
    });

    describe('Provisioning Complexity', () => {
        it('should show complexity breakdown for supported modules', () => {
            const byComplexity = {};
            
            for (const mod of supportedModules) {
                const complexity = mod.provisioning_complexity || 'unknown';
                if (!byComplexity[complexity]) byComplexity[complexity] = 0;
                byComplexity[complexity]++;
            }
            
            console.log('\n🔧 PROVISIONING COMPLEXITY (Supported Modules Only):\n');
            for (const [complexity, count] of Object.entries(byComplexity).sort((a, b) => b[1] - a[1])) {
                console.log(`  ${complexity}: ${count}`);
            }
        });
    });


    // ============================================================================
    // Summary Report (Runs after all tests)
    // ============================================================================
    afterAll(() => {
        console.log('\n' + '='.repeat(80));
        console.log('LUDUS TEMPLATE COMPATIBILITY SUMMARY');
        console.log('='.repeat(80));
        console.log(`Total Modules:          ${modules?.length || 0}`);
        console.log(`Supported:              ${supportedModules?.length || 0}`);
        console.log(`Unsupported:            ${unsupportedModules?.length || 0}`);
        console.log(`Special Requirements:   ${specialRequirementModules?.length || 0}`);
        console.log('='.repeat(80));
        
        if (unsupportedModules?.length > 0) {
            console.log('\n⚠️  ACTION REQUIRED:');
            console.log('   - Add Ludus templates for missing Windows versions');
            console.log('   - Or map unsupported versions to closest available template');
            console.log('   - Consider creating custom templates for legacy OS (2000, XP, 2003, etc.)');
        }
        
        if (specialRequirementModules?.length > 0) {
            console.log('\n⚠️  ANSIBLE ROLES REQUIRED:');
            console.log('   - badsectorlabs.ludus_commandovm');
            console.log('   - badsectorlabs.ludus_flarevm');
            console.log('   - badsectorlabs.ludus_remnux');
        }
        
        console.log('\n📄 Full unsupported module list saved to console above');
        console.log('='.repeat(80) + '\n');
    });
});

// ============================================================================
// Export for programmatic use
// ============================================================================
export {
    extractWindowsVersion,
    getLudusTemplate,
    isTemplateSupported,
    getSpecialRequirements,
    LUDUS_TEMPLATES,
    WINDOWS_TEMPLATE_MAP
};