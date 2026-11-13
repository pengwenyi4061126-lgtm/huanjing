#pragma once

// Registers the current process with the signed CacKernel control plane. The
// registration is evidence and lifecycle state; it does not spoof host
// hardware or replace the NativeBridge API hooks.
bool KernelPolicyRequired();
bool RegisterCurrentProcessKernelPolicy();
