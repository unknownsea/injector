#pragma once
#include <string>
#include <windows.h>

bool InjectDLL(DWORD pid, const std::string& dllPath);