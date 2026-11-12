#!/usr/bin/env node
var path = require('path');
var fs = require('fs');

var pkgDir = path.join(__dirname, '..');
var cacBin = path.join(pkgDir, 'cac');
var home = process.env.HOME || process.env.USERPROFILE || '';
var cacDir = path.join(home, '.cac');

// Ensure cac is executable
try { fs.chmodSync(cacBin, 0o755); } catch (e) {}

// Windows: override npm-generated shims (cac.cmd, cac.ps1) to use PowerShell version.
// npm auto-generates shims that call `bash cac`, but on Windows the system `bash`
// may point to WSL which can't resolve Windows paths. Our cac.ps1 is the native
// Windows entry point, so we make the shims call it directly.
if (process.platform === 'win32') {
  try {
    var npmBin = path.dirname(process.env.npm_node_execpath
      ? path.join(path.dirname(process.env.npm_node_execpath), '..', 'bin')
      : '');
    // Find the npm global bin dir by locating where our shim lives
    var shimCmd = path.join(pkgDir, '..', '..', 'cac.cmd');
    if (!fs.existsSync(shimCmd)) {
      // Fallback: npm prefix
      var spawnSync = require('child_process').spawnSync;
      var result = spawnSync('npm', ['prefix', '-g'], { encoding: 'utf8', shell: true });
      if (result.stdout) {
        shimCmd = path.join(result.stdout.trim(), 'cac.cmd');
      }
    }
    if (fs.existsSync(shimCmd)) {
      var shimDir = path.dirname(shimCmd);
      var cacPs1Src = path.join(pkgDir, 'cac.ps1');
      if (fs.existsSync(cacPs1Src)) {
        // cac.cmd → tries pwsh first, falls back to powershell.exe
        fs.writeFileSync(path.join(shimDir, 'cac.cmd'), [
          '@echo off',
          'where pwsh >nul 2>&1 && (',
          '    pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0node_modules\\cac-windows\\cac.ps1" %*',
          '    exit /b %ERRORLEVEL%',
          ')',
          'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0node_modules\\cac-windows\\cac.ps1" %*',
          ''
        ].join('\r\n'));
        // cac.ps1 shim — tries pwsh first, falls back to powershell.exe
        fs.writeFileSync(path.join(shimDir, 'cac.ps1'), [
          '$cacDir = Join-Path (Split-Path $MyInvocation.MyCommand.Definition -Parent) "node_modules\\cac-windows"',
          'if (Get-Command pwsh -ErrorAction SilentlyContinue) { $ps = "pwsh" } else { $ps = "powershell.exe" }',
          '& $ps -NoProfile -ExecutionPolicy Bypass -File "$cacDir\\cac.ps1" @args',
          'exit $LASTEXITCODE',
          ''
        ].join('\r\n'));
      }
    }
  } catch (e) {
    // Non-fatal — user can manually run: pwsh cac.ps1
  }
}

// ── Windows: ensure correct Claude Code version is installed and patched ──
// Handles three cases automatically:
//   1. Claude Code not installed → install pinned version
//   2. Claude Code wrong version → reinstall pinned version
//   3. install.cjs not run (allow-scripts blocked) → run it
//   4. TZ patch not applied → apply it
var SUPPORTED_CLAUDE_VERSION = '2.1.294';
var CC_PKG = '@anthropic-ai/claude-code';
if (process.platform === 'win32') {
  var spawnSync = require('child_process').spawnSync;
  var npmPrefix = process.env.npm_config_prefix || path.join(home, 'AppData', 'Roaming', 'npm');
  var ccDir = path.join(npmPrefix, 'node_modules', CC_PKG);
  var ccBinDir = path.join(ccDir, 'bin');
  var ccInstall = path.join(ccDir, 'install.cjs');
  var ccPkgJson = path.join(ccDir, 'package.json');

  // Step 1: Check if Claude Code is installed
  var needInstall = false;
  if (!fs.existsSync(ccPkgJson)) {
    console.log('  Claude Code not found — installing v' + SUPPORTED_CLAUDE_VERSION + '...');
    needInstall = true;
  } else {
    try {
      var ccVersion = JSON.parse(fs.readFileSync(ccPkgJson, 'utf8')).version;
      if (ccVersion !== SUPPORTED_CLAUDE_VERSION) {
        console.log('  Claude Code v' + ccVersion + ' detected (TZ patch supports v' + SUPPORTED_CLAUDE_VERSION + ').');
        console.log('  TZ patch will be skipped. Other cac features work normally.');
        console.log('  To get TZ support: npm i -g ' + CC_PKG + '@' + SUPPORTED_CLAUDE_VERSION);
      }
    } catch (e) { needInstall = true; }
  }

  if (needInstall) {
    var installResult = spawnSync('npm', ['install', '-g', CC_PKG + '@' + SUPPORTED_CLAUDE_VERSION,
      '--registry', 'https://registry.npmjs.org'], {
      encoding: 'utf8', shell: true, stdio: 'inherit', timeout: 120000
    });
    if (installResult.status !== 0) {
      console.log('  \x1b[33m⚠ Claude Code install failed\x1b[0m — install manually:');
      console.log('    npm i -g ' + CC_PKG + '@' + SUPPORTED_CLAUDE_VERSION);
    }
  }

  // Step 2: Ensure install.cjs has run (extracts the SEA binary)
  try {
    var hasExe = fs.existsSync(path.join(ccBinDir, 'claude.exe')) || fs.existsSync(path.join(ccBinDir, 'claude'));
    if (!hasExe && fs.existsSync(ccInstall)) {
      console.log('  Running Claude Code install.cjs (blocked by allow-scripts)...');
      spawnSync(process.execPath, [ccInstall], { stdio: 'inherit', timeout: 30000 });
    }
  } catch (e) { /* non-fatal */ }

  // Step 3: Apply TZ + privacy patches (single source of truth: scripts/patch-cli.js)
  // Skipped if claude is running (binary locked → EBUSY); `cac` will patch on next launch.
  try {
    var patchScript = path.join(__dirname, 'patch-cli.js');
    var tl = spawnSync('tasklist', ['/FI', 'IMAGENAME eq claude.exe', '/NH'], { encoding: 'utf8', timeout: 10000 });
    var claudeRunning = tl.stdout && /claude\.exe/i.test(tl.stdout);
    if (claudeRunning) {
      console.log('  Claude Code is running — skipping patch. Run `cac` after closing it to patch.');
    } else if (fs.existsSync(patchScript)) {
      spawnSync(process.execPath, [patchScript, ccDir], { stdio: 'inherit', timeout: 120000 });
    }
  } catch (e) {
    // Non-fatal — patches are optional; cac works without them
  }
}

var quickStart = [
  '',
  '  cac-windows installed successfully',
  '',
  '  Next: run  cac  — it patches Claude Code, sets PATH, and opens the menu.',
  '  Then open a NEW terminal and type  claude',
  ''
];
console.log(quickStart.join('\n'));
