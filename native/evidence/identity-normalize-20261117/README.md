# Cross-profile identity normalization — 2026-11-17

## Before

`scripts\profile-identity-check.ps1` reported 24 failures:

- `desktop\1` and `desktop\audit-clean` shared
  `machine_id=7105ecbcb4a642a685ea9848ddd5d3ba` and
  `uuid=B9BE6964-2380-4FAD-9BF1-BAC5064448E9`.
- `desktop\1`, `desktop\profile-a/b` and all `envs\*` still used `02:xx`
  locally-administered MACs and `host-*` hostnames.
- Only `desktop\audit-clean` had `realism_schema=2`.

## Actions

1. Ran `scripts\profile-identity-normalize.ps1 -RegenerateDevice 'desktop\1'`.
   - `desktop\1` received a new `machine_id`, `uuid`, `stable_id` and derived
     serials/MAC/hostname.
   - All other profiles were migrated in place to `realism_schema=2`
     (vendor OUI MAC, `DESKTOP-XXXXXXX`, vendor-format serials, `nic_pci_id`).
   - Each changed `identity.json` has an `identity.json.bak-<timestamp>`
     sibling.
2. `desktop\audit-clean` was already at schema 2 and was left unchanged, so
   the existing verifier evidence remains valid.
3. Ran `scripts\profile-identity-check.ps1`: **pass** (see `after.txt`).

## Host LWF removal

The host no longer has the NDIS filter installed:

```text
netcfg -u CacMacLwf                      -> done
pnputil /delete-driver oem16.inf /uninstall /force -> deleted
sc delete CacMacLwf                      -> SUCCESS
```

Verification:

```text
C:\Windows\System32\drivers\CacMacLwf.sys  False
C:\Windows\INF\oem16.inf                   False
Get-NetAdapterBinding -ComponentID CacMacLwf  0 rows
sc query CacMacLwf                         1060 (service does not exist)
```

The repository `native\macfilter\bin` build and VM evidence remain for
isolated test use only.
