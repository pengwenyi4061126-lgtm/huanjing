#pragma once

// Hides virtual/tunnel adapters from enumeration and forces proxy queries to
// DIRECT when the Profile uses CAC_NETWORK_MODE=clean (or empty reads).
void InstallNetworkHooks();
