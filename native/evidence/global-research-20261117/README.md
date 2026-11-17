# Global device-identity research — 2026-11-17

Scope: current public techniques for Windows device/HWID identity, compared
with this repository's userland NativeBridge + VMX-static-MAC approach.

## Sources

- GitHub search (2026-11-17): `hwid spoofer`, `smbios spoof`,
  `disk serial spoofer`, `edid spoof`, `qemu smbios`, `hypervisor detection`.
- QEMU documentation: `-smbios` types 0/1/2/3/4/17 and per-NIC `mac=`.
  https://www.qemu.org/docs/master/system/invocation.html
- libvirt domain XML: `<sysinfo type='smbios'>`, `<smbios mode='sysinfo'>`,
  `<uuid>`, `<mac address=...>`, disk `<serial>`.
  https://libvirt.org/formatdomain.html
- arXiv 2025-2026: GPU fingerprinting for location verification
  (2605.01930), FP-Agent (2605.01247), browser fingerprinting via V8
  bytecode (2509.09950) and WebAssembly (2506.00719).
- Hacker News: “Chrome's New AI Web APIs Are Enabling Hardware
  Fingerprinting”; “Windows VM detection tricks part 2 – driver thread
  fingerprinting”.
- Stack Overflow: ATA PASS-THROUGH IDENTIFY DEVICE on RAID/SSD.
- Microsoft/OSR NDIS semantics (see `native/macfilter/evidence/web-20261117`).

## Frontier layers

| Layer | Representative work | What it buys |
| --- | --- | --- |
| VM/hypervisor identity | QEMU/libvirt SMBIOS types, UUID, per-NIC MAC, disk serial, OVMF/TPM | True per-profile isolation; guest sees generated hardware |
| Kernel static patch (no hook) | `btbd/hwid`, `SamuelTulach/mutante`, `Alex3434/wmi-static-spoofer` | Disk/volume/NIC+ARP/SMBIOS/boot/GPU IDs; driver can unload |
| EFI/pre-boot | `SamuelTulach/negativespoofer` | SMBIOS patched before Windows boots |
| DMA/external | `vibheksoni/dma-spoofer` | 12 modules: SMBIOS, disk, NIC, GPU, monitor, volume, registry, TPM, EFI, boot, ARP, USB; dxgkrnl EDID cache |
| Userland API hooks | this project | Fast, per-process, no kernel risk; incomplete by design |
| Browser JS shims | WebGL/canvas/audio shims | Covers JS-readable surfaces; WebGPU/WebNN less covered |

## Verified gaps in this project

1. **ATA PASS-THROUGH leaks real disk identity.**
   `cac-ata-probe.exe` sends ATA IDENTIFY DEVICE via
   `IOCTL_ATA_PASS_THROUGH`. Outside and inside injection both return:

   ```text
   ata_model=CJ325060BC
   ata_serial=F4DJ13000878
   ata_firmware=1.00
   ```

   The descriptor/SMART patches do not cover pass-through IDENTIFY.
   Source: `native/AtaProbe/main.cpp`; build with the repo MSVC toolchain
   (`toolchain.ps1` + `cl /std:c++17 /MT /O2`).

2. **CIM/MI network queries leak the real MAC and virtual adapters.**
   `Get-NetAdapter` and `Get-CimInstance Win32_NetworkAdapter` inside
   injection still show `0A-E0-AF-B1-2C-E1` plus VMware/Meta adapters.
   The COM `IWbemLocator` wrapper is bypassed by MI/CIM.

3. **USB raw descriptors / hub IOCTLs are not hooked** (code-level gap;
   SetupDi and HID strings are covered, but `IOCTL_USB_GET_*` is not).

4. **Vulkan Properties2 / D3D12 static structures** — only
   `vkGetPhysicalDeviceProperties` and DXGI are hooked.

5. **ARP/neighbor tables, dxgkrnl EDID cache, TPM/EFI/boot state** — not
   covered; public DMA/kernel projects explicitly target these.

6. **WebGPU/WebNN** — WebGL vendor/renderer is shimmed; WebGPU adapter
   info and AI Web APIs are not.

## What this project covers better than typical public tools

- WMI COM PnP/monitor (`WmiMonitorID` arrays)/SMART/firmware/cache/audio
  with a 108-check verifier.
- NVMe identify SN/MN/FR (btbd/hwid explicitly notes NVMe IOCTLs are not
  handled).
- HID report descriptor, USB PnP graph, process hiding, clean network mode.
- Cross-profile identity uniqueness gate.

## Recommendation order

1. Hook `IOCTL_ATA_PASS_THROUGH[_DIRECT]` and
   `IOCTL_SCSI_PASS_THROUGH[_DIRECT]` INQUIRY/IDENTIFY buffers; add the ATA
   probe to the verifier.
2. Decide CIM/MI: either hook the MI API, or accept it as a boundary and
   use a stable LWF/VM for network identity. A stable LWF can plausibly fix
   NDIS-backed MAC queries, but not CIM BIOS/disk/GPU and not per-process.
3. Add Vulkan `vkGetPhysicalDeviceProperties2`, WebGPU shim, USB hub
   descriptor hooks.
4. For bare-metal consistency, kernel static patching or EFI SMBIOS is the
   public frontier, but carries HVCI/driver-blocklist/detection risk.
5. For true isolation, generate identity at VM definition (QEMU/libvirt
   SMBIOS/UUID/MAC/disk serial/TPM) instead of spoofing inside Windows.
