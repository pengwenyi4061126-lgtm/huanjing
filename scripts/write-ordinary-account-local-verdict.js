'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const root = path.resolve(__dirname, '..');
const tag = process.argv[2] || new Date().toISOString().replace(/[-:TZ.]/g, '').slice(0, 14);
const outDir = path.join(root, 'native', 'evidence', 'claude-coverage', `ordinary-account-local-verdict-${tag}`);
if (fs.existsSync(outDir)) throw new Error(`output already exists: ${outDir}`);
fs.mkdirSync(outDir, { recursive: true });

function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex').toUpperCase();
}

function rel(file) {
  return path.relative(root, file).replaceAll(path.sep, '/');
}

function evidence(file, label) {
  const record = { label, path: file, relativePath: rel(file), exists: fs.existsSync(file) };
  if (record.exists) {
    const stat = fs.statSync(file);
    record.bytes = stat.size;
    record.sha256 = sha256(file);
  } else {
    record.bytes = 0;
    record.sha256 = null;
  }
  return record;
}

const contractJson = path.join(root, 'CLAUDE-COVERAGE-GOAL-V2.json');
const contractMd = path.join(root, 'CLAUDE-COVERAGE-GOAL-V2.md');
const contract = JSON.parse(fs.readFileSync(contractJson, 'utf8'));
const g0 = path.join(root, 'native/evidence/claude-coverage/g0-freeze-current-20261126-112215/g0-freeze.json');
const g5c = path.join(root, 'native/evidence/claude-coverage/g5c-v231-alternating-20261125-0500/g5c-verification.json');
const g6 = path.join(root, 'native/evidence/claude-coverage/g6-reconciliation-local-rev32-20261126-resume/delivery-reconciliation.json');
const memory = path.join(root, 'native/evidence/claude-coverage/g6-memory-module-existing-20261126-continue-local-r2/actual-memory-module-ledger.json');
const g7 = path.join(root, 'native/evidence/claude-coverage/g7-review-v232-20261126-continue/g7-review.json');
const g1b = path.join(root, 'native/evidence/claude-coverage/g1b-current-rev32-20261126-continue/closure.json');
const profileRuntime = path.join(root, 'native/evidence/claude-coverage/current-profile1-runtime-20261126-continue-r3/current-profile1-runtime.json');
const lifecycle = path.join(root, 'native/evidence/claude-coverage/profile1-direct-lifecycle-20261126-130141067/verification.json');
const p2 = path.join(root, 'native/evidence/claude-coverage/p2-input-gate-20261125-0520/requirements.json');

const evidenceFiles = [
  evidence(contractJson, 'coverage-contract-json'),
  evidence(contractMd, 'coverage-contract-markdown'),
  evidence(g0, 'G0-source-and-profile-freeze'),
  evidence(g5c, 'G5c-alternating-profile-verification'),
  evidence(g6, 'G6-current-delivery-reconciliation'),
  evidence(memory, 'G6-current-mapped-memory-ledger'),
  evidence(g1b, 'G1b-current-revision-closure'),
  evidence(profileRuntime, 'current-Profile1-runtime-readonly'),
  evidence(lifecycle, 'Profile1-direct-lifecycle-regression'),
  evidence(g7, 'G7-independent-review'),
  evidence(p2, 'P2-external-input-gate')
];

const report = {
  schema: 'ordinary-account-local-verdict/v1',
  generatedUtc: new Date().toISOString(),
  target: {
    product: 'Claude Desktop',
    version: '5.1231.2.0',
    architecture: 'Windows x64 MSIX',
    packageRoot: 'C:\\Program Files\\WindowsApps\\Claude_5.1231.2.0_x64__pzs8sxrjxfjjc\\app',
    rawMsixReadOnly: true
  },
  contract: {
    revision: String(contract.revision),
    markdownSha256: sha256(contractMd),
    declaredMarkdownSha256: String(contract.contract_sha256),
    jsonSha256: sha256(contractJson),
    bindingMatch: sha256(contractMd) === String(contract.contract_sha256)
  },
  baseline: {
    accountClass: 'ordinary-account',
    profileId: '1',
    profileRoot: 'C:\\Users\\Administrator\\.cac\\desktop\\1',
    loginStatus: 'known-success-baseline',
    cacheStatus: 'available-and-restarted',
    cacheLifecycleEvidenceRoot: lifecycle,
    currentRootPid: null,
    launchRootPids: [13120, 13620],
    finalClaudeProcessCount: 0,
    noTokenCookieDpapiOrPasswordExport: true
  },
  crr: {
    total: 61,
    statusCounts: { pass: 41, fail: 0, unverified: 9, unsupported: 9, notApplicable: 2 },
    unverifiedIds: ['A-01', 'A-02', 'A-03', 'L-03', 'M-03', 'M-04', 'R-05', 'R-06', 'S-02'],
    unsupportedIds: ['B-08', 'L-06', 'N-01', 'N-02', 'N-03', 'N-04', 'N-06', 'R-03', 'S-05'],
    notApplicableIds: ['A-05', 'B-02']
  },
  localGates: {
    prelogin_local_profile_pass: {
      status: 'pass-bounded',
      final: true,
      reason: 'G0/G5c profile isolation, current-revision executable rollback, and two direct Profile 1 launch/restart runs are closed; graceful-stop behavior remains an explicit lifecycle boundary.'
    },
    ordinary_account_local_verdict: {
      status: 'local-scope-pass-with-explicit-boundaries',
      final: true,
      reason: 'All currently reachable ordinary-account local evidence is closed; deferred external-input surfaces and the graceful-stop boundary remain explicit.'
    },
    supported_subset_pass: false,
    anti_association_pass: false,
    functional_pass: false
  },
  verified: {
    g0SourceFreeze: 'pass',
    g5cAlternatingRuns: { status: 'pass-bounded', runs: 8, bare: 4, injected: 4, alternatingRounds: 2 },
    profileConsistency: 'pass',
    profileAbyDifference: 'pass',
    negativeLeakage: 'pass-bounded',
    networkUnchanged: true,
    actualClaudeModuleLoad: 'pass',
    mappedMemoryHash: 'pass',
    coreNativeDeploymentSync: 'pass',
    g1bSourceClosure: 'pass',
    profile1Runtime: 'pass-bounded',
    profile1Lifecycle: {
      status: 'pass-bounded-controlled-stop',
      directLaunchRuns: 2,
      antDidStable: true,
      gracefulStop: 'failed-rc-2-both-runs',
      controlledStop: 'pass-rc-0-both-runs',
      finalClaudeProcessCount: 0,
      evidenceRoot: lifecycle
    },
    g7IndependentReview: 'pass'
  },
  deferredExternalInput: {
    classification: 'blocked-external-input',
    ids: ['A-01', 'A-02', 'A-03', 'L-03', 'M-03', 'M-04', 'R-05', 'R-06', 'S-02'],
    rule: 'Do not use CDP, pushState, shim, or probe self-calls to manufacture runtime evidence.'
  },
  unsupportedBoundaries: {
    ids: ['B-08', 'L-06', 'N-01', 'N-02', 'N-03', 'N-04', 'N-06', 'R-03', 'S-05'],
    rule: 'Each boundary remains separately reported with its original evidence; unsupported is not pass.'
  },
  g6: {
    currentRevisionMemoryHash: 'pass',
    currentRevisionFileSync: 'pass',
    liveRollback: 'pass-executable-live-rollback',
    blockingReason: null,
    blockers: []
  },
  stopRules: {
    doNotRepeatPassedScenarios: true,
    doNotAddUnreachableHardwareProbes: true,
    doNotRepeatLogin: true,
    doNotChangeHostNetwork: true,
    diskFreeGiBObserved: 21.61,
    diskFloorGiB: 12,
    evidenceRootGiBObserved: 2.313
  },
  evidence: evidenceFiles
};

const jsonPath = path.join(outDir, 'ordinary-account-local-verdict.json');
fs.writeFileSync(jsonPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');

const markdown = [
  '# Ordinary-account local verdict',
  '',
  `- Contract: ${report.contract.revision}`,
  `- Contract Markdown SHA256: ${report.contract.markdownSha256}`,
  `- Target: ${report.target.product} ${report.target.version} ${report.target.architecture}`,
  '- Raw MSIX: read-only',
  '- Account/Profile: ordinary account, Profile 1, known-good cache baseline',
  '',
  '## Result',
  '',
  `- prelogin_local_profile_pass: **${report.localGates.prelogin_local_profile_pass.status}**`,
  `- ordinary_account_local_verdict: **${report.localGates.ordinary_account_local_verdict.status}**`,
  '- supported_subset_pass: **false**',
  '- anti_association_pass: **false**',
  '- functional_pass: **false**',
  '',
  '## CRR 61',
  '',
  '- 41 pass, 0 fail, 9 unverified, 9 unsupported, 2 N/A.',
  '- Unverified entries are blocked-external-input and are not silently downgraded.',
  '- Unsupported entries retain their boundary evidence and do not count as pass.',
  '',
  '## G6 boundary',
  '',
  '- Current-revision file sync, actual module load, mapped-image hashes, and executable live rollback pass.',
  `- Profile 1 lifecycle: two direct launches succeeded with stable ant-did; graceful stop returned rc=2 in both runs, then Profile-scoped controlled stop returned rc=0 with zero Claude residuals.`,
  '',
  '## Deferred',
  '',
  '- Cowork, computer-use, real MCP, post-login feature flags, real TelemetryEvent, server opaque body, and second-account switch tests remain deferred.',
  '- No CDP, pushState, shim, or probe self-call is used to manufacture evidence.',
  '',
  '## Evidence',
  '',
  ...evidenceFiles.map((item) => `- ${item.label}: ${item.relativePath} (${item.sha256 || 'missing'})`),
  ''
].join('\n');
const mdPath = path.join(outDir, 'ordinary-account-local-verdict.md');
fs.writeFileSync(mdPath, markdown, 'utf8');

const files = [jsonPath, mdPath].map((file) => ({ path: file, bytes: fs.statSync(file).size, sha256: sha256(file) }));
fs.writeFileSync(path.join(outDir, 'sha256-manifest.json'), `${JSON.stringify({ schema: 1, generatedUtc: new Date().toISOString(), files }, null, 2)}\n`, 'utf8');
console.log(JSON.stringify({ outputRoot: outDir, json: jsonPath, markdown: mdPath, status: report.localGates.ordinary_account_local_verdict.status, blockers: report.g6.blockers }, null, 2));
