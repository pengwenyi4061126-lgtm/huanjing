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
  var npmCommand = 'npm.cmd';

  function failPostinstall(message) {
    console.error('  cac-windows postinstall failed: ' + message);
    process.exit(1);
  }

  function resolveNpmCli() {
    var lifecycleCli = process.env.npm_execpath;
    if (lifecycleCli && fs.existsSync(lifecycleCli)) return lifecycleCli;

    var located = spawnSync('where.exe', [npmCommand], {
      encoding: 'utf8',
      shell: false,
      windowsHide: true,
      timeout: 10000
    });
    if (!located.error && located.status === 0) {
      var npmCmdPath = String(located.stdout || '').split(/\r?\n/)
        .map(function (line) { return line.trim(); })
        .filter(function (line) { return line.length > 0; })[0];
      if (npmCmdPath) {
        var cliPath = path.join(path.dirname(npmCmdPath), 'node_modules', 'npm', 'bin', 'npm-cli.js');
        if (fs.existsSync(cliPath)) return cliPath;
      }
    }
    return null;
  }

  var npmCli = resolveNpmCli();

  function spawnNpm(args, options) {
    var spawnOptions = Object.assign({
      shell: !npmCli,
      windowsHide: true
    }, options || {});
    if (npmCli) return spawnSync(process.execPath, [npmCli].concat(args), spawnOptions);
    return spawnSync(npmCommand, args, spawnOptions);
  }

  function getNpmGlobalPrefix() {
    var result = spawnNpm(['prefix', '-g'], {
      encoding: 'utf8',
      windowsHide: true,
      timeout: 30000
    });
    if (result.error || result.status !== 0) {
      failPostinstall('npm prefix -g failed' + (result.error ? ': ' + result.error.message : ''));
    }
    var lines = String(result.stdout || '').split(/\r?\n/)
      .map(function (line) { return line.trim(); })
      .filter(function (line) { return line.length > 0; });
    var prefix = lines.length > 0 ? lines[lines.length - 1] : '';
    if (!prefix) failPostinstall('npm prefix -g returned an empty path');
    return path.resolve(prefix);
  }

  function installClaudeCode(npmPrefix) {
    console.log('  Installing Claude Code v' + SUPPORTED_CLAUDE_VERSION + ' from npm prefix ' + npmPrefix + '...');
    var installResult = spawnNpm([
      'install', '-g', CC_PKG + '@' + SUPPORTED_CLAUDE_VERSION,
      '--registry', 'https://registry.npmjs.org'
    ], {
      stdio: 'inherit',
      windowsHide: false,
      timeout: 120000
    });
    if (installResult.error || installResult.status !== 0) {
      failPostinstall('Claude Code v' + SUPPORTED_CLAUDE_VERSION + ' installation failed' +
        (installResult.error ? ': ' + installResult.error.message : ''));
    }
  }

  var npmPrefix = getNpmGlobalPrefix();
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
        console.log('  Claude Code v' + ccVersion + ' detected; cac-windows requires v' + SUPPORTED_CLAUDE_VERSION + ' for its pinned patch set.');
        console.log('  Reinstalling the pinned Claude Code version now.');
        needInstall = true;
      }
    } catch (e) {
      console.log('  Claude Code package metadata is unreadable; reinstalling the pinned version.');
      needInstall = true;
    }
  }

  if (needInstall) {
    installClaudeCode(npmPrefix);
  }

  // Re-read the package after a reinstall and refuse to continue on drift.
  if (!fs.existsSync(ccPkgJson)) {
    failPostinstall('Claude Code package is still missing after installation');
  }
  try {
    var installedVersion = JSON.parse(fs.readFileSync(ccPkgJson, 'utf8')).version;
    if (installedVersion !== SUPPORTED_CLAUDE_VERSION) {
      failPostinstall('Claude Code version mismatch after installation: found ' + installedVersion +
        ', expected ' + SUPPORTED_CLAUDE_VERSION);
    }
  } catch (e) {
    failPostinstall('Claude Code package metadata is unreadable after installation: ' + e.message);
  }

  // Step 2: Ensure install.cjs has run (extracts the SEA binary)
  try {
    var hasExe = fs.existsSync(path.join(ccBinDir, 'claude.exe')) || fs.existsSync(path.join(ccBinDir, 'claude'));
    if (!hasExe) {
      if (!fs.existsSync(ccInstall)) {
        failPostinstall('Claude Code executable is missing and install.cjs is unavailable');
      }
      console.log('  Running Claude Code install.cjs (blocked by allow-scripts)...');
      var installScriptResult = spawnSync(process.execPath, [ccInstall], {
        stdio: 'inherit',
        windowsHide: false,
        timeout: 30000
      });
      if (installScriptResult.error || installScriptResult.status !== 0) {
        failPostinstall('Claude Code install.cjs failed' +
          (installScriptResult.error ? ': ' + installScriptResult.error.message : ''));
      }
      hasExe = fs.existsSync(path.join(ccBinDir, 'claude.exe')) || fs.existsSync(path.join(ccBinDir, 'claude'));
      if (!hasExe) failPostinstall('Claude Code executable is still missing after install.cjs');
    }
  } catch (e) {
    failPostinstall('Claude Code executable setup failed: ' + e.message);
  }

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
