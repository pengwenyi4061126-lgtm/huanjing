#pragma once

// Installs in-process COM wrappers for CLSID_WbemLocator. Query results are
// rewritten before they reach the caller so WMI/COM hardware reads follow the
// same Profile policy as the Win32 API hooks.
void InstallWmiHooks();
