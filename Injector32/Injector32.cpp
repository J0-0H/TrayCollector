// Injector32Main.cpp
// 编译平台：Win32 / x86。
// 用法：Injector32.exe <目标PID> <32位DLL完整路径

#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <string>

#include "../Common/InjectHelper.h"

int wmain(int argc, wchar_t* argv[])
{
    if (argc < 3)
        return 2;

    DWORD pid = static_cast<DWORD>(
        _wtoi(argv[1]));

    if (pid == 0)
        return 3;

    std::wstring dllPath = argv[2];

    EnableDebugPrivilegeSelf();

    return InjectDllSameArch(
        pid,
        dllPath) ? 0 : 1;
}
