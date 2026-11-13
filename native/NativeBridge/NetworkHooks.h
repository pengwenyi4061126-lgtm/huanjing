#pragma once

// Hides virtual/tunnel adapters from selected process-local enumerations and
// forces proxy queries to DIRECT when the Profile uses CAC_NETWORK_MODE=clean
// (or empty reads). GetBestRoute2 is observed for audit only; this layer does
// not change Windows routing or the server-visible exit path.
void InstallNetworkHooks();
