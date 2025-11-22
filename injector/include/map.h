#pragma once
#include <windows.h>
#include <vector>
#include <cstdint>

bool ManualMapDLL(HANDLE hProcess, const uint8_t* dllBuffer, size_t dllSize);