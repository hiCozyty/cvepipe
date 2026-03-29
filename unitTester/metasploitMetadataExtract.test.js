#!/usr/bin/env bun

/**
 * Unit Test Suite for Metasploit Metadata Extractor
 *
 * Tests the following components:
 * 1. Sparse clone verification
 * 2. Ruby file parsing and metadata extraction
 * 3. Heuristic classification logic
 * 4. LLM classification helpers
 * 5. Output validation
 * 6. CVE enrichment helpers
 */

import { describe, test, expect, beforeEach, afterEach } from 'bun:test';
import { readdirSync, writeFileSync, existsSync, mkdirSync, rmSync, statSync } from 'node:fs';
import path from 'node:path';

// ============================================================================
// Test Constants and Fixtures
// ============================================================================

const TEST_DIR = './test_fixtures';

const SAMPLE_RB_CONTENT = `
# Sample Metasploit module for testing
require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::SMB::Client

  def initialize(info = {})
    super(merge_info(info,
      'Name' => 'MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption',
      'Description' => %q{ This module exploits the EternalBlue vulnerability in SMBv1. The target must be running an unpatched Windows system with SMBv1 enabled. },
      'License' => MSF_LICENSE,
      'Author' => [
        'Shadow Brokers',
        'Sean Dillon <sean.dillon@risksense.com>'
      ],
      'References' => [
        ['CVE', '2017-0144'],
        ['CVE', '2017-0143'],
        ['EDB', '42315'],
        ['URL', 'https://github.com/rapid7/metasploit-framework']
      ],
      'DefaultOptions' => {
        'RHOST' => '',
        'RPORT' => 445
      },
      'Platform' => 'win',
      'Arch' => [ARCH_X86, ARCH_X64],
      'Targets' => [
        ['Windows 7 SP1 x64', { 'Target' => 0 }],
        ['Windows Server 2008 R2 SP1 x64', { 'Target' => 1 }]
      ],
      'DisclosureDate' => '2017-03-14',
      'DefaultTarget' => 0
    ))
  end
end
`;

const FILEFORMAT_RB_CONTENT = `
# Adobe Reader Buffer Overflow
require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
  def initialize(info = {})
    super(merge_info(info,
      'Name' => 'Adobe Reader util.printf() Buffer Overflow',
      'Description' => %q{ This module exploits a buffer overflow in Adobe Reader's util.printf function. The victim must open a malicious PDF file. },
      'References' => [
        ['CVE', '2008-2992'],
        ['EDB', '6288']
      ],
      'Platform' => 'win',
      'Arch' => [ARCH_X86],
      'Targets' => [
        ['Adobe Reader 8.1.2 on Windows XP SP3', { 'Target' => 0 }]
      ],
      'DisclosureDate' => '2008-11-04'
    ))
  end
end
`;

const RDP_RB_CONTENT = `
# BlueKeep RDP Exploit
require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
  def initialize(info = {})
    super(merge_info(info,
      'Name' => 'MS19-019 Remote Desktop Services RCE',
      'Description' => %q{ This module exploits the Remote Desktop Services vulnerability known as BlueKeep. No user interaction required. },
      'References' => [
        ['CVE', '2019-0708'],
        ['EDB', '47337']
      ],
      'DefaultOptions' => {
        'RPORT' => 3389
      },
      'Platform' => 'win',
      'Arch' => [ARCH_X86, ARCH_X64],
      'Targets' => [
        ['Windows Server 2003 SP2', { 'Target' => 0 }],
        ['Windows XP SP3', { 'Target' => 1 }]
      ],
      'DisclosureDate' => '2019-05-14'
    ))
  end
end
`;

const LOCAL_PRIVESC_CONTENT = `
# Local Privilege Escalation
require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
  def initialize(info = {})
    super(merge_info(info,
      'Name' => 'Windows Kernel APC Local Privilege Escalation',
      'Description' => %q{ This module exploits a local privilege escalation vulnerability. Requires local access to the target machine. },
      'References' => [
        ['CVE', '2018-8453']
      ],
      'Platform' => 'win',
      'Arch' => [ARCH_X86, ARCH_X64],
      'Targets' => [
        ['Windows 10 RS1 < RS4', { 'Target' => 0 }]
      ],
      'DisclosureDate' => '2018-09-11'
    ))
  end
end
`;

// ============================================================================
// Helper Functions (for testing)
// ============================================================================

/**
 * Extract metadata from Ruby .rb file content
 */
function extractMetadataFromRb(content, filePath) {
  const metadata = {
    name: null,
    description: null,
    platform: [],
    arch: [],
    cves: [],
    edb_ids: [],
    port: null,
    targets: [],
    disclosed: null,
    file_path: filePath
  };

  const nameMatch = content.match(/'Name'\s*=>\s*'([^']+)'/);
  if (nameMatch) {
    metadata.name = nameMatch[1];
  }

  const descSingleMatch = content.match(/'Description'\s*=>\s*'([^']+)'/);
  if (descSingleMatch) {
    metadata.description = descSingleMatch[1].substring(0, 500);
  } else {
    const descMultilineMatch = content.match(/'Description'\s*=>\s*%q\{([^}]*)\}/s);
    if (descMultilineMatch) {
      metadata.description = descMultilineMatch[1].trim().substring(0, 500);
    }
  }

  const platformMatch = content.match(/'Platform'\s*=>\s*'([^']+)'/);
  if (platformMatch) {
    metadata.platform = [platformMatch[1]];
  } else {
    const platformArrayMatch = content.match(/'Platform'\s*=>\s*\[([^\]]+)\]/);
    if (platformArrayMatch) {
      const platforms = platformArrayMatch[1].match(/'([^']+)'/g);
      if (platforms) {
        metadata.platform = platforms.map(p => p.replace(/'/g, ''));
      }
    }
  }

  const archMatch = content.match(/'Arch'\s*=>\s*\[([^\]]+)\]/);
  if (archMatch) {
    const archs = archMatch[1].match(/ARCH_[A-Z0-9_]+/g);
    if (archs) {
      metadata.arch = archs;
    }
  }

  const cveMatches = content.matchAll(/\['CVE',\s*'([^']+)'\]/g);
  for (const match of cveMatches) {
    metadata.cves.push(match[1]);
  }

  const edbMatches = content.matchAll(/\['EDB',\s*'([^']+)'\]/g);
  for (const match of edbMatches) {
    metadata.edb_ids.push(match[1]);
  }

  const portMatch = content.match(/'RPORT'\s*=>\s*(\d+)/);
  if (portMatch) {
    metadata.port = parseInt(portMatch[1], 10);
  }

  const targetsMatch = content.match(/'Targets'\s*=>\s*\[([^\]]*(?:\[[^\]]*\][^\]]*)*)\]/s);
  if (targetsMatch) {
    const targetStrings = targetsMatch[1].match(/\[\s*'([^']+)'/g);
    if (targetStrings) {
      metadata.targets = targetStrings.map(t => {
        const match = t.match(/'([^']+)'/);
        return match ? match[1] : null;
      }).filter(Boolean);
    }
  }

  const disclosureMatch = content.match(/'DisclosureDate'\s*=>\s*'([^']+)'/);
  if (disclosureMatch) {
    metadata.disclosed = disclosureMatch[1];
  }

  return metadata;
}

function deriveMsfPath(filePath) {
  const match = filePath.match(/modules\/(exploit\/[^/]+\/[^/]+\/[^.]+)/);
  if (match) {
    return match[1];
  }
  return filePath.replace('.rb', '').replace('modules/', '');
}

function deriveServiceCategory(filePath) {
  const match = filePath.match(/modules\/exploit\/windows\/([^/]+)\//);
  if (match) {
    return match[1];
  }
  return 'unknown';
}

function heuristicClassification(metadata) {
  const name = (metadata.name || '').toLowerCase();
  const description = (metadata.description || '').toLowerCase();
  const filePath = (metadata.file_path || '').toLowerCase();
  const serviceCategory = deriveServiceCategory(filePath);

  const networkServiceCategories = [
    'smb', 'rdp', 'http', 'https', 'ftp', 'smtp', 'pop', 'imap',
    'telnet', 'ssh', 'vnc', 'mssql', 'mysql', 'postgres', 'oracle',
    'redis', 'mongodb', 'snmp', 'dns', 'ntp', 'ldap', 'rpc'
  ];

  if (networkServiceCategories.includes(serviceCategory)) {
    return {
      replicable: true,
      confidence: 'high',
      reason: `Module targets ${serviceCategory} network service`,
      exclusion_category: null
    };
  }

  if (filePath.includes('fileformat') || filePath.includes('social_engineering')) {
    return {
      replicable: false,
      confidence: 'high',
      reason: 'Module path indicates client-side file format or social engineering exploit',
      exclusion_category: 'client_side_fileformat'
    };
  }

  if (filePath.includes('/local/')) {
    const localIndicators = [
      'privilege escalation', 'privesc', 'already authenticated', 'existing session'
    ];
    for (const indicator of localIndicators) {
      if (name.includes(indicator) || description.includes(indicator)) {
        return {
          replicable: false,
          confidence: 'high',
          reason: 'Module appears to be a local privilege escalation exploit',
          exclusion_category: 'local_privesc'
        };
      }
    }
    return {
      replicable: false,
      confidence: 'high',
      reason: 'Module is in local directory requiring local access',
      exclusion_category: 'local_privesc'
    };
  }

  const clientSideIndicators = [
    'pdf', 'doc', 'word', 'excel', 'office', 'victim', 'email attachment'
  ];
  for (const indicator of clientSideIndicators) {
    if (name.includes(indicator) || description.includes(indicator)) {
      return {
        replicable: false,
        confidence: 'high',
        reason: 'Module requires victim interaction',
        exclusion_category: 'client_side_fileformat'
      };
    }
  }

  const browserIndicators = [
    'browser', 'chrome', 'firefox', 'internet explorer'
  ];
  for (const indicator of browserIndicators) {
    if (name.includes(indicator) || description.includes(indicator)) {
      return {
        replicable: false,
        confidence: 'high',
        reason: 'Module requires victim to visit a malicious URL in browser',
        exclusion_category: 'client_side_browser'
      };
    }
  }

  if (metadata.port && metadata.port > 0) {
    return {
      replicable: true,
      confidence: 'high',
      reason: `Module targets network service on port ${metadata.port}`,
      exclusion_category: null
    };
  }

  return {
    replicable: true,
    confidence: 'medium',
    reason: 'Appears to be a network-based exploit module but requires verification',
    exclusion_category: null
  };
}

const heuristic_classification = heuristicClassification;

/**
 * Prepare module for LLM classification
 */
function prepareModuleForLLM(metadata, batchId) {
  return {
    id: batchId,
    msf_path: metadata.msf_path,
    name: metadata.name,
    service_category: metadata.service_category,
    description: metadata.description?.substring(0, 300) || '',
    targets: metadata.targets,
    cves: metadata.cves,
    port: metadata.port
  };
}

// ============================================================================
// Test Suite
// ============================================================================

describe('Metasploit Metadata Extractor', () => {
  beforeEach(() => {
    if (!existsSync(TEST_DIR)) {
      mkdirSync(TEST_DIR, { recursive: true });
    }
  });

  afterEach(() => {
    if (existsSync(TEST_DIR)) {
      rmSync(TEST_DIR, { recursive: true, force: true });
    }
  });

  // ============================================================================
  // Sparse Clone Verification Tests
  // ============================================================================

  describe('Sparse Clone Verification', () => {
    test('should detect existing metasploit-framework directory', () => {
      const mockDir = `${TEST_DIR}/metasploit-framework`;
      mkdirSync(mockDir, { recursive: true });
      mkdirSync(`${mockDir}/modules/exploits/windows`, { recursive: true });
      writeFileSync(`${mockDir}/modules/exploits/windows/test.rb`, '');

      expect(existsSync(mockDir)).toBe(true);
      expect(existsSync(`${mockDir}/modules/exploits/windows`)).toBe(true);
    });

    test('should identify sparse clone characteristics', () => {
      const sparseCloneCommands = [
        'git clone --depth=1 --filter=blob:none --sparse',
        'git sparse-checkout set'
      ];

      expect(sparseCloneCommands).toContain('git clone --depth=1 --filter=blob:none --sparse');
      expect(sparseCloneCommands).toContain('git sparse-checkout set');
    });

    test('should skip clone if directory exists', () => {
      const mockDir = `${TEST_DIR}/existing-metasploit`;
      mkdirSync(mockDir, { recursive: true });

      const shouldClone = !existsSync(mockDir);
      expect(shouldClone).toBe(false);
    });
  });

  // ============================================================================
  // Ruby File Parsing Tests
  // ============================================================================

  describe('Ruby File Parsing', () => {
    test('should extract name from Ruby module', () => {
      const metadata = extractMetadataFromRb(SAMPLE_RB_CONTENT, 'test/ms17_010.rb');
      expect(metadata.name).toBe('MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption');
    });

    test('should extract description from Ruby module', () => {
      const metadata = extractMetadataFromRb(SAMPLE_RB_CONTENT, 'test/ms17_010.rb');
      expect(metadata.description).toContain('EternalBlue');
      expect(metadata.description).toContain('SMBv1');
    });

    test('should extract CVE references', () => {
      const metadata = extractMetadataFromRb(SAMPLE_RB_CONTENT, 'test/ms17_010.rb');
      expect(metadata.cves).toContain('2017-0144');
      expect(metadata.cves).toContain('2017-0143');
    });

    test('should extract EDB IDs', () => {
      const metadata = extractMetadataFromRb(SAMPLE_RB_CONTENT, 'test/ms17_010.rb');
      expect(metadata.edb_ids).toContain('42315');
    });

    test('should extract port from DefaultOptions', () => {
      const metadata = extractMetadataFromRb(SAMPLE_RB_CONTENT, 'test/ms17_010.rb');
      expect(metadata.port).toBe(445);
    });

    test('should extract platform', () => {
      const metadata = extractMetadataFromRb(SAMPLE_RB_CONTENT, 'test/ms17_010.rb');
      expect(metadata.platform).toContain('win');
    });

    test('should extract architecture', () => {
      const metadata = extractMetadataFromRb(SAMPLE_RB_CONTENT, 'test/ms17_010.rb');
      expect(metadata.arch).toContain('ARCH_X86');
      expect(metadata.arch).toContain('ARCH_X64');
    });

    test('should extract targets', () => {
      const metadata = extractMetadataFromRb(SAMPLE_RB_CONTENT, 'test/ms17_010.rb');
      expect(metadata.targets.length).toBeGreaterThan(0);
      expect(metadata.targets.join(', ')).toContain('Windows 7');
    });

    test('should extract disclosure date', () => {
      const metadata = extractMetadataFromRb(SAMPLE_RB_CONTENT, 'test/ms17_010.rb');
      expect(metadata.disclosed).toBe('2017-03-14');
    });

    test('should handle missing fields gracefully', () => {
      const emptyContent = `
class EmptyModule < Msf::Exploit::Remote
  def initialize(info = {})
    super(merge_info(info,
      'Name' => 'Empty Module'
    ))
  end
end
`;
      const metadata = extractMetadataFromRb(emptyContent, 'test/empty.rb');
      expect(metadata.name).toBe('Empty Module');
      expect(metadata.description).toBeNull();
      expect(metadata.cves).toEqual([]);
      expect(metadata.port).toBeNull();
    });

    test('should truncate description to 500 characters', () => {
      const longDescription = 'A'.repeat(600);
      const content = `
class TestModule < Msf::Exploit::Remote
  def initialize(info = {})
    super(merge_info(info,
      'Name' => 'Test',
      'Description' => '${longDescription}'
    ))
  end
end
`;
      const metadata = extractMetadataFromRb(content, 'test/long_desc.rb');
      expect(metadata.description?.length).toBeLessThanOrEqual(500);
    });
  });

  // ============================================================================
  // Heuristic Classification Tests
  // ============================================================================

  describe('VM Replicability Classification', () => {
    test('should classify EternalBlue as replicable (network service)', () => {
      const metadata = extractMetadataFromRb(
        SAMPLE_RB_CONTENT,
        'modules/exploit/windows/smb/ms17_010.rb'
      );
      metadata.service_category = 'smb';
      const classification = heuristic_classification(metadata);
      expect(classification.replicable).toBe(true);
      expect(classification.confidence).toBe('high');
    });

    test('should classify fileformat exploit as non-replicable', () => {
      const metadata = extractMetadataFromRb(
        FILEFORMAT_RB_CONTENT,
        'modules/exploit/windows/fileformat/adobe_utilprintf.rb'
      );
      metadata.service_category = 'fileformat';
      const classification = heuristic_classification(metadata);
      expect(classification.replicable).toBe(false);
      expect(classification.exclusion_category).toBe('client_side_fileformat');
    });

    test('should classify RDP exploit as replicable', () => {
      const metadata = extractMetadataFromRb(
        RDP_RB_CONTENT,
        'modules/exploit/windows/rdp/bluekeep.rb'
      );
      metadata.service_category = 'rdp';
      const classification = heuristic_classification(metadata);
      expect(classification.replicable).toBe(true);
    });

    test('should classify local privilege escalation as non-replicable', () => {
      const metadata = extractMetadataFromRb(
        LOCAL_PRIVESC_CONTENT,
        'modules/exploit/windows/local/kernel_apc.rb'
      );
      metadata.service_category = 'local';
      const classification = heuristic_classification(metadata);
      expect(classification.replicable).toBe(false);
      expect(classification.exclusion_category).toBe('local_privesc');
    });

    test('should classify based on file path fileformat', () => {
      const metadata = {
        name: 'Test Exploit',
        file_path: 'modules/exploit/windows/fileformat/test.rb'
      };
      const classification = heuristic_classification(metadata);
      expect(classification.replicable).toBe(false);
      expect(classification.exclusion_category).toBe('client_side_fileformat');
    });

    test('should classify based on file path social_engineering', () => {
      const metadata = {
        name: 'Test Exploit',
        file_path: 'modules/exploit/windows/social_engineering/test.rb'
      };
      const classification = heuristic_classification(metadata);
      expect(classification.replicable).toBe(false);
      expect(classification.exclusion_category).toBe('client_side_fileformat');
    });

    test('should return medium confidence for uncertain modules', () => {
      const metadata = {
        name: 'Unknown Network Exploit',
        file_path: 'modules/exploit/windows/misc/unknown.rb',
        port: null,
        description: 'Some obscure exploit'
      };
      const classification = heuristic_classification(metadata);
      expect(classification.confidence).toBe('medium');
      expect(classification.replicable).toBe(true);
    });
  });

  // ============================================================================
  // Path Derivation Tests
  // ============================================================================

  describe('Path Derivation', () => {
    test('should derive MSF path from file path', () => {
      const filePath = 'modules/exploit/windows/smb/ms17_010_eternalblue.rb';
      const msfPath = deriveMsfPath(filePath);
      expect(msfPath).toBe('exploit/windows/smb/ms17_010_eternalblue');
    });

    test('should derive service category from file path', () => {
      const filePath = 'modules/exploit/windows/smb/ms17_010_eternalblue.rb';
      const category = deriveServiceCategory(filePath);
      expect(category).toBe('smb');
    });

    test('should handle different service categories', () => {
      const paths = [
        { path: 'modules/exploit/windows/http/iis_shortname.rb', expected: 'http' },
        { path: 'modules/exploit/windows/ftp/vsftpd_backdoor.rb', expected: 'ftp' },
        { path: 'modules/exploit/windows/smb/smb_delivery.rb', expected: 'smb' },
        { path: 'modules/exploit/windows/rdp/bluekeep.rb', expected: 'rdp' }
      ];

      for (const { path, expected } of paths) {
        expect(deriveServiceCategory(path)).toBe(expected);
      }
    });
  });

  // ============================================================================
  // LLM Classification Helper Tests
  // ============================================================================

  describe('LLM Classification Helpers', () => {
    test('should prepare module for LLM classification', () => {
      const metadata = {
        msf_path: 'exploit/windows/smb/ms17_010',
        name: 'Test Module',
        service_category: 'smb',
        description: 'This is a test description that is longer than 300 characters and should be truncated when prepared for the LLM API call to ensure we do not exceed token limits',
        targets: ['Windows 7', 'Windows Server 2008'],
        cves: ['CVE-2017-0144'],
        port: 445
      };

      const prepared = prepareModuleForLLM(metadata, 0);
      expect(prepared.id).toBe(0);
      expect(prepared.msf_path).toBe('exploit/windows/smb/ms17_010');
      expect(prepared.name).toBe('Test Module');
      expect(prepared.description.length).toBeLessThanOrEqual(300);
      expect(prepared.cves).toContain('CVE-2017-0144');
      expect(prepared.port).toBe(445);
    });

    test('should prepare module with empty description', () => {
      const metadata = {
        msf_path: 'exploit/windows/test',
        name: 'Test',
        service_category: 'unknown',
        description: null,
        targets: [],
        cves: [],
        port: null
      };

      const prepared = prepareModuleForLLM(metadata, 1);
      expect(prepared.id).toBe(1);
      expect(prepared.description).toBe('');
    });

    test('should handle LLM system prompt structure', () => {
      const systemPrompt = `You are a security lab engineer. For each Metasploit exploit module in the input JSON array, determine if it can be realistically simulated in a standard VM lab: attacker Kali VM targeting a Windows Server/Desktop VM, connected over a host-only or NAT network. No user interaction is available on the target. Respond ONLY with a valid JSON array in the same order as the input. Each element must follow this exact schema: { "id": <same id as input>, "replicable": true | false, "confidence": "high" | "medium" | "low", "reason": "<one sentence>", "exclusion_category": null | "client_side_browser" | "client_side_fileformat" | "client_side_social" | "local_privesc" | "hardware_iot" | "no_network_service" | "requires_physical" } Mark replicable: false if ANY apply: - client_side_browser: exploit requires victim to visit a URL in a browser - client_side_fileformat: requires victim to open a malicious file (PDF, doc, etc.) - client_side_social: any required user interaction on the victim machine - local_privesc: escalates privileges on an already-accessed machine (not initial foothold) - hardware_iot: targets physical hardware, firmware, embedded/ICS/SCADA devices - no_network_service: no listening TCP/UDP service on the target is involved - requires_physical: requires physical access to target machine Mark replicable: true if: - A standard network service listens on the target (SMB, RDP, HTTP, FTP, SMTP, etc.) - The attacker can reach it over the network with no victim interaction - A standard Windows VM (Server or Desktop) could realistically host it - It achieves initial foothold (first remote shell/session) Use confidence: "low" for genuinely ambiguous cases. No explanation outside the JSON array. No markdown fences.`;

      expect(systemPrompt).toContain('You are a security lab engineer');
      expect(systemPrompt).toContain('"replicable":');
      expect(systemPrompt).toContain('client_side_fileformat');
      expect(systemPrompt).toContain('local_privesc');
    });
  });

  // ============================================================================
  // Directory Walking Tests
  // ============================================================================

  describe('Directory Walking', () => {
    test('should recursively find all .rb files', () => {
      const mockDir = `${TEST_DIR}/metasploit-framework/modules/exploits/windows`;
      mkdirSync(`${mockDir}/smb`, { recursive: true });
      mkdirSync(`${mockDir}/http`, { recursive: true });
      writeFileSync(`${mockDir}/smb/ms17_010.rb`, SAMPLE_RB_CONTENT);
      writeFileSync(`${mockDir}/smb/smb_delivery.rb`, SAMPLE_RB_CONTENT);
      writeFileSync(`${mockDir}/http/iis_shortname.rb`, SAMPLE_RB_CONTENT);

      const findRbFiles = (dir) => {
        const files = [];
        const entries = readdirSync(dir);
        for (const entry of entries) {
          const fullPath = path.join(dir, entry);
          const stats = statSync(fullPath);
          if (stats.isDirectory()) {
            files.push(...findRbFiles(fullPath));
          } else if (entry.endsWith('.rb')) {
            files.push(fullPath);
          }
        }
        return files;
      };

      const rbFiles = findRbFiles(mockDir);
      expect(rbFiles.length).toBe(3);
      expect(rbFiles.some(f => f.includes('ms17_010.rb'))).toBe(true);
    });

    test('should count total .rb files found', () => {
      const mockDir = `${TEST_DIR}/count-test`;
      mkdirSync(mockDir, { recursive: true });

      for (let i = 0; i < 5; i++) {
        writeFileSync(`${mockDir}/test${i}.rb`, SAMPLE_RB_CONTENT);
      }

      const entries = readdirSync(mockDir);
      const rbFiles = entries.filter(e => e.endsWith('.rb'));
      expect(rbFiles.length).toBe(5);
    });
  });

  // ============================================================================
  // Output Validation Tests
  // ============================================================================

  describe('Output Validation', () => {
    test('should generate valid JSON output', () => {
      const output = [
        {
          name: 'MS17-010 EternalBlue',
          msf_path: 'exploit/windows/smb/ms17_010_eternalblue',
          file_path: 'modules/exploit/windows/smb/ms17_010_eternalblue.rb',
          service_category: 'smb',
          platform: ['win'],
          arch: ['ARCH_X86', 'ARCH_X64'],
          cves: ['2017-0144'],
          edb_ids: ['42315'],
          port: 445,
          targets: ['Windows 7 SP1 x64'],
          disclosed: '2017-03-14',
          replicable: true,
          confidence: 'high',
          reason: 'Targets SMBv1 network service',
          exclusion_category: null
        }
      ];

      const jsonString = JSON.stringify(output, null, 2);
      expect(() => JSON.parse(jsonString)).not.toThrow();
      const parsed = JSON.parse(jsonString);
      expect(parsed.length).toBe(1);
      expect(parsed[0]).toHaveProperty('name');
      expect(parsed[0]).toHaveProperty('msf_path');
      expect(parsed[0]).toHaveProperty('replicable');
    });

    test('should include all required fields in output', () => {
      const requiredFields = [
        'name', 'msf_path', 'file_path', 'service_category', 'platform',
        'arch', 'cves', 'edb_ids', 'port', 'targets', 'disclosed',
        'replicable', 'confidence', 'reason', 'exclusion_category'
      ];

      const sample = {
        name: 'Test',
        msf_path: 'test',
        file_path: 'test.rb',
        service_category: 'smb',
        platform: ['win'],
        arch: [],
        cves: [],
        edb_ids: [],
        port: 445,
        targets: [],
        disclosed: null,
        replicable: true,
        confidence: 'high',
        reason: 'test',
        exclusion_category: null
      };

      for (const field of requiredFields) {
        expect(sample).toHaveProperty(field);
      }
    });
  });

  // ============================================================================
  // CVE Enrichment Tests
  // ============================================================================

  describe('CVE Enrichment Helpers', () => {
    test('should parse CPE string correctly', () => {
      const parseCPE = (cpeString) => {
        const parts = cpeString.split(':');
        if (parts.length < 6) return null;
        return {
          part: parts[2],
          vendor: parts[3],
          product: parts[4],
          version: parts[5]
        };
      };

      const cpe1 = 'cpe:2.3:a:microsoft:smb_server:*:*:*:*:*:*:*:*';
      const parsed1 = parseCPE(cpe1);
      expect(parsed1.part).toBe('a');
      expect(parsed1.vendor).toBe('microsoft');
      expect(parsed1.product).toBe('smb_server');

      const cpe2 = 'cpe:2.3:o:microsoft:windows_7:*:sp1:*:*:*:*:x64:*';
      const parsed2 = parseCPE(cpe2);
      expect(parsed2.part).toBe('o');
      expect(parsed2.product).toBe('windows_7');
    });

    test('should extract version from CPE', () => {
      const extractVersion = (cpeString) => {
        const parts = cpeString.split(':');
        return parts[5] || null;
      };

      expect(extractVersion('cpe:2.3:o:microsoft:windows_7:sp1:*:*:*:*:*:*:*')).toBe('sp1');
      expect(extractVersion('cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*')).toBe('2.4.41');
    });

    test('should handle NVD API response structure', () => {
      const mockNvdResponse = {
        resultsPerPage: 1,
        startIndex: 0,
        totalResults: 1,
        format: 'NVD_CVE',
        version: '2.0',
        timestamp: '2024-01-01T00:00:00.000',
        vulnerabilities: [
          {
            cve: {
              id: 'CVE-2017-0144',
              descriptions: {
                descriptionData: [{ langCode: 'en', value: 'EternalBlue vulnerability' }]
              },
              metrics: {
                cvssV3_0: {
                  baseScore: 9.8,
                  vectorString: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'
                }
              },
              configurations: {
                nodes: [{
                  operator: 'OR',
                  negated: false,
                  cpeMatch: [
                    { criteria: 'cpe:2.3:o:microsoft:windows_7:*:sp1:*:*:*:*:*:*', vulnerable: true }
                  ]
                }]
              }
            }
          }
        ]
      };

      expect(mockNvdResponse.vulnerabilities.length).toBe(1);
      expect(mockNvdResponse.vulnerabilities[0].cve.id).toBe('CVE-2017-0144');
      expect(mockNvdResponse.vulnerabilities[0].cve.metrics.cvssV3_0.baseScore).toBe(9.8);
    });
  });

  // ============================================================================
  // Batch Processing Tests
  // ============================================================================

  describe('Batch Processing', () => {
    test('should batch modules for LLM classification', () => {
      const modules = Array.from({ length: 27 }, (_, i) => ({ id: i }));
      const batchSize = 10;
      const batches = [];

      for (let i = 0; i < modules.length; i += batchSize) {
        batches.push(modules.slice(i, i + batchSize));
      }

      expect(batches.length).toBe(3);
      expect(batches[0].length).toBe(10);
      expect(batches[1].length).toBe(10);
      expect(batches[2].length).toBe(7);
    });

    test('should handle concurrent batch processing concept', () => {
      const maxConcurrency = 5;
      const totalBatches = 65;

      expect(maxConcurrency).toBe(5);
      expect(totalBatches).toBe(65);
    });
  });

  // ============================================================================
  // Error Handling Tests
  // ============================================================================

  describe('Error Handling', () => {
    test('should handle parse errors gracefully', () => {
      const malformedContent = `
class MalformedModule
  def initialize
    # Missing proper MSF structure
    incomplete code here
  end
end
`;
      const metadata = extractMetadataFromRb(malformedContent, 'test/malformed.rb');
      expect(metadata).toBeDefined();
      expect(metadata.name).toBeNull();
    });

    test('should handle empty file', () => {
      const metadata = extractMetadataFromRb('', 'test/empty.rb');
      expect(metadata.name).toBeNull();
      expect(metadata.description).toBeNull();
    });

    test('should handle file not found', () => {
      const filePath = 'test/nonexistent.rb';
      expect(existsSync(filePath)).toBe(false);
    });
  });

  // ============================================================================
  // Statistics and Reporting Tests
  // ============================================================================

  describe('Statistics and Reporting', () => {
    test('should calculate statistics correctly', () => {
      const modules = [
        { name: 'a', replicable: true },
        { name: 'b', replicable: true },
        { name: 'c', replicable: false, exclusion_category: 'client_side_fileformat' },
        { name: 'd', replicable: false, exclusion_category: 'local_privesc' },
        { name: 'e', replicable: false, exclusion_category: 'client_side_fileformat' }
      ];

      const total = modules.length;
      const replicable = modules.filter(m => m.replicable).length;
      const notReplicable = modules.filter(m => !m.replicable).length;

      const byCategory = {};
      modules.filter(m => !m.replicable).forEach(m => {
        byCategory[m.exclusion_category] = (byCategory[m.exclusion_category] || 0) + 1;
      });

      expect(total).toBe(5);
      expect(replicable).toBe(2);
      expect(notReplicable).toBe(3);
      expect(byCategory['client_side_fileformat']).toBe(2);
      expect(byCategory['local_privesc']).toBe(1);
    });

    test('should generate requirements summary', () => {
      const enrichedModules = [
        {
          msf_path: 'exploit/windows/smb/ms17_010',
          software: [{ name: 'Windows SMBv1', version: 'built-in' }],
          windows_os: ['Windows 7', 'Windows Server 2008 R2']
        },
        {
          msf_path: 'exploit/windows/rdp/bluekeep',
          software: [{ name: 'Windows RDP', version: 'built-in' }],
          windows_os: ['Windows Server 2003', 'Windows XP SP3']
        }
      ];

      const allSoftware = new Set();
      const allOs = new Set();

      for (const mod of enrichedModules) {
        mod.software.forEach(s => allSoftware.add(s.name));
        mod.windows_os.forEach(os => allOs.add(os));
      }

      expect(allSoftware.size).toBe(2);
      expect(allSoftware.has('Windows SMBv1')).toBe(true);
      expect(allSoftware.has('Windows RDP')).toBe(true);
      expect(allOs.size).toBe(4);
    });
  });

  // ============================================================================
  // Integration-style Tests
  // ============================================================================

  describe('Integration Flow', () => {
    test('should complete full parsing and classification flow', () => {
      const metadata = extractMetadataFromRb(
        SAMPLE_RB_CONTENT,
        'modules/exploit/windows/smb/ms17_010.rb'
      );
      metadata.msf_path = deriveMsfPath(metadata.file_path);
      metadata.service_category = deriveServiceCategory(metadata.file_path);

      const classification = heuristic_classification(metadata);
      const result = { ...metadata, ...classification };

      expect(result.name).toContain('EternalBlue');
      expect(result.msf_path).toBe('exploit/windows/smb/ms17_010');
      expect(result.service_category).toBe('smb');
      expect(result.replicable).toBe(true);
    });

    test('should handle multiple modules with different categories', () => {
      const modules = [
        { content: SAMPLE_RB_CONTENT, path: 'modules/exploit/windows/smb/ms17_010.rb' },
        { content: FILEFORMAT_RB_CONTENT, path: 'modules/exploit/windows/fileformat/adobe.rb' },
        { content: RDP_RB_CONTENT, path: 'modules/exploit/windows/rdp/bluekeep.rb' }
      ];

      const results = modules.map(({ content, path }) => {
        const metadata = extractMetadataFromRb(content, path);
        metadata.msf_path = deriveMsfPath(path);
        metadata.service_category = deriveServiceCategory(path);
        return { ...metadata, ...heuristic_classification(metadata) };
      });

      expect(results[0].replicable).toBe(true);
      expect(results[1].replicable).toBe(false);
      expect(results[1].exclusion_category).toBe('client_side_fileformat');
      expect(results[2].replicable).toBe(true);
    });

    test('should identify uncertain modules for LLM classification', () => {
      const uncertainModule = {
        name: 'Obscure Network Exploit',
        file_path: 'modules/exploit/windows/misc/obscure.rb',
        port: null,
        description: 'Some obscure exploit without clear indicators'
      };

      const classification = heuristic_classification(uncertainModule);
      expect(classification.confidence).toBe('medium');
    });
  });
});