#pragma once

// Installs an optional dynamic WFP boundary for the current process. The
// boundary allows loopback proxy connections and blocks non-loopback outbound
// ALE connect traffic. It is disabled unless CAC_NETWORK_ENFORCE is enabled.
bool WfpPolicyRequired();
bool InstallWfpBoundary();
