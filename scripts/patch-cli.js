const fs = require("fs");
const path = require("path");
const ccDir = process.argv[2] || path.join(process.env.APPDATA, "npm", "node_modules", "@anthropic-ai", "claude-code");

// Marker strings only exist in a patched binary (padding spaces never occur in minified source)
const TZ_MARKER = 'Intl.DateTimeFormat("sv",{timeZone:process.env.TZ||"UTC"}).format(new Date)   ';
const PRIVACY_MARKER = '=process.env.TZ||"UTC"   ';

// 2.1.294 signatures — minified names change every release, re-extract with find-sigs.js
const tzPats = [
  ['function Ano(){let e=new Date,t=Rno();if(t!==void 0){let s=new Map(R4("en-US",{timeZone:t,year:"numeric",month:"2-digit",day:"2-digit"}).formatToParts(e).map((c)=>[c.type,c.value]));return`${s.get("year")}-${s.get("month")}-${s.get("day")}`}let n=e.getFullYear(),r=String(e.getMonth()+1).padStart(2,"0"),p=String(e.getDate()).padStart(2,"0");return`${n}-${r}-${p}`}',
   'function Ano(){return new Intl.DateTimeFormat("sv",{timeZone:process.env.TZ||"UTC"}).format(new Date)                                                                                                                                                                                                                                                                       }'],
];

const privacyPats = [
  ['function y_o(){if(!g)g=Intl.DateTimeFormat().resolvedOptions().timeZone;return g}',
   'function y_o(){if(!g)g=process.env.TZ||"UTC"                           ;return g}'],
  ['function hSs(){if(l===null)try{let e=Intl.DateTimeFormat().resolvedOptions().locale;l=new Intl.Locale(e).language}catch{l=void 0}return l}',
   'function hSs(){if(l===null)l="en";                                                                                               return l}'],
  ['let A=Intl.DateTimeFormat().resolvedOptions().timeZone',
   'let A=process.env.TZ||"UTC"                           '],
  ['.toLocaleDateString(void 0,{year:"numeric",month:"short",day:"numeric"})',
   '.toLocaleDateString( "en" ,{year:"numeric",month:"short",day:"numeric"})'],
  ['Se=-Q.getTimezoneOffset(),Me=Math.floor(Math.abs(Se)/60),Ie=Math.abs(Se)%60,Fe=`${Se>=0?"+":"-"}${String(Me).padStart(2,"0")}:${String(Ie).padStart(2,"0")}`',
   'Se=0                                                                                                                                  ,Me=0,Ie=0,Fe="+00:00"'],
];

const binDir = path.join(ccDir, "bin");
const seaCandidates = ["claude.exe", "claude"].map(n => path.join(binDir, n)).filter(p => fs.existsSync(p));

if (seaCandidates.length === 0) {
  console.log("  No patchable binary found in " + binDir);
  process.exit(0);
}

function applyPats(bytes, text, pats) {
  let n = 0;
  for (const [o, r] of pats) {
    if (o.length !== r.length) { console.log("  length mismatch, skipped: " + o.slice(0, 30)); continue; }
    const idx = text.indexOf(o);
    if (idx === -1) continue;
    Buffer.from(r, "latin1").copy(bytes, idx);
    n++;
  }
  return n;
}

let exitCode = 0;
for (const exe of seaCandidates) {
  const name = path.basename(exe);
  let bytes = fs.readFileSync(exe);
  let text = bytes.toString("latin1");
  const msgs = [];
  let changed = false;

  if (text.includes(TZ_MARKER)) {
    msgs.push("TZ patch already applied");
  } else {
    const n = applyPats(bytes, text, tzPats);
    if (n > 0) { changed = true; msgs.push("TZ patch applied"); }
    else msgs.push("TZ patch skipped — signature not found");
  }

  if (text.includes(PRIVACY_MARKER)) {
    msgs.push("Privacy patches already applied");
  } else {
    const n = applyPats(bytes, text, privacyPats);
    if (n > 0) { changed = true; msgs.push("Privacy patches applied " + n + "/" + privacyPats.length); }
    else msgs.push("Privacy patches skipped — signatures not found");
  }

  if (changed) {
    // Write FIRST, report after — a locked binary (claude running) must not be reported as patched.
    try {
      if (!fs.existsSync(exe + ".bak")) fs.copyFileSync(exe, exe + ".bak");
      fs.writeFileSync(exe, bytes);
    } catch (e) {
      exitCode = 1;
      if (e.code === "EBUSY" || e.code === "EPERM") {
        console.log("  PATCH FAILED (" + name + "): binary is locked — close all Claude Code sessions and retry");
      } else {
        console.log("  PATCH FAILED (" + name + "): " + e.message);
      }
      continue;
    }
  }
  msgs.forEach(m => console.log("  " + m + " (" + name + ")"));
}
process.exit(exitCode);
