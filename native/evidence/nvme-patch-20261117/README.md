# NVMe identify transformation — 2026-11-17

The host disk is SATA, so an end-to-end NVMe identify query cannot be
captured here. The transformation used by the hook is now a shared inline
function (`native/NativeBridge/StorageIdentity.h`) and has a standalone
regression:

```powershell
native\dist\cac-nvme-patch-test.exe
```

Output:

```text
nvme_patch_test=pass
nvme_patch_serial=TESTSERIAL123
nvme_patch_model=TESTMODEL
nvme_patch_firmware=1.2.3
```

The test builds a `STORAGE_PROTOCOL_DATA_DESCRIPTOR` with
`ProtocolTypeNvme`, `DataType=Identify`, calls the same
`cac::PatchNvmeIdentifyBuffer` used by `SanitizeStorageOutput`, and asserts
the SN/MN/FR fields. End-to-end NVMe hardware evidence remains blocked by
the absent device.
