# MAC mode research sources — 2026-11-17

Raw pages were fetched for verification and are kept locally; this file
records the exact quotes used in the review.

## Microsoft Learn

- FILTER_PAUSE — “NDIS drivers cannot fail a pause request.”
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ndis/nc-ndis-filter_pause
- NdisFSendNetBufferListsComplete — “A filter driver calls the
  NdisFSendNetBufferListsComplete function to complete send requests that
  NDIS made to the driver's FilterSendNetBufferLists function.”
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ndis/nf-ndis-ndisfsendnetbufferlistscomplete
- NdisReadNetworkAddress — returns the software-configurable address stored
  in the registry; the driver must validate it and otherwise use the
  permanent MAC or a default.
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ndis/nf-ndis-ndisreadnetworkaddress
- Set-NetAdapter — “Not all network adapters support setting the MAC
  address.” / “These changes could disrupt proper networking functionality.”
  https://learn.microsoft.com/en-us/powershell/module/netadapter/set-netadapter
- Set-NetAdapterAdvancedProperty
  https://learn.microsoft.com/en-us/powershell/module/netadapter/set-netadapteradvancedproperty

## Microsoft sample

- ndislwf `filter.c` — Pause comment: “No other return value is allowed
  (pause must succeed, eventually).”; send/return completion forwards to
  `NdisFSendNetBufferListsComplete` / `NdisFReturnNetBufferLists`.
  https://github.com/microsoft/Windows-driver-samples/blob/main/network/ndis/filter/filter.c

## OSR (Microsoft engineer)

- Jeffrey Tippet (MSFT): “I'm not sure it's really possible to replace a
  MAC address from a LWF. … Simply editing one OID isn't enough to notify
  NDIS and the world to update all their various caches.”
  https://community.osr.com/discussion/290816/ndis-filter-modifying-an-adapters-mac-address

## Intel

- Locally Administered Address: replaces the adapter MAC, does not change
  the burned-in address; 12 hex digits; no multicast; no all-0/all-F.
  https://www.intel.com/content/www/us/en/support/articles/000005593/network-and-i-o/ethernet-products.html

## SpoofMAC

- Windows note: `getmac` / `ipconfig` may still show the original address
  depending on the NIC.
  https://github.com/feross/SpoofMAC
