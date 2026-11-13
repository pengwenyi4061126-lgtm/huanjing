#pragma once

#include <windows.h>
#include <string>

void AuditInit(const std::wstring& profileDir);
void AuditEvent(const char* surface, const char* action, const char* detail = nullptr,
                unsigned long long value = 0, bool hasValue = false);
void AuditEventRateLimited(const char* surface, const char* action, const char* detail = nullptr,
                           unsigned long long value = 0, bool hasValue = false);
