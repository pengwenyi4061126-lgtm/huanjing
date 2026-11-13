#pragma once

#include <windows.h>

#include "Identity.h"

// Rewrites serial/UUID/processor fields inside a raw SMBIOS table in place.
// String values are truncated to their original byte length and padded with
// spaces so the SMBIOS string-set layout and all offsets stay valid.
// `buffer` may include the 8-byte RawSMBIOSData header (auto-detected).
bool PatchSmbiosBuffer(BYTE* buffer, DWORD length, const ProfileIdentity& identity, int* patchedFields);
