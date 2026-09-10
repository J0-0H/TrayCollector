// InjectHelper.h
// 注意：CreateRemoteThread 注入只能在"调用者进程位数 == 目标进程位数"时使用。
// 64位目标 -> 必须由64位进程调用 InjectDllSameArch()
// 32位目标 -> 必须由32位进程调用 InjectDllSameArch()（也就是 Injector32.exe）
// 这是 Windows 的硬限制，不是实现细节问题。
#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <string>

inline void InjLog(const std::wstring& s)
{
    OutputDebugStringW((L"[InjectHelper] " + s + L"\r\n").c_str());
}

inline bool EnableDebugPrivilegeSelf()
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
    bool ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr) != 0
        && GetLastError() != ERROR_NOT_ALL_ASSIGNED;
    CloseHandle(hToken);
    return ok;
}

// 唯一权威的"注入是否真正成功"判据：直接去目标进程的模块表里找这个 DLL。
// 不能靠远线程退出码——64位目标下 LoadLibraryW 返回的指针会被截断成32位 DWORD 存放，
// 理论上不可靠；更不能像原来那样只看 CreateRemoteThread 有没有创建成功。
inline bool IsModuleLoadedInProcess(DWORD pid, const std::wstring& dllPath)
{
    std::wstring target = dllPath;
    size_t slash = target.find_last_of(L"\\/");
    if (slash != std::wstring::npos) target = target.substr(slash + 1);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        InjLog(L"IsModuleLoadedInProcess: 快照失败 pid=" + std::to_wstring(pid) + L" err=" + std::to_wstring(GetLastError()));
        return false;
    }

    bool found = false;
    MODULEENTRY32W me{ sizeof(me) };
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, target.c_str()) == 0) { found = true; break; }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

// 经典的 LoadLibrary 远线程注入。要求调用者进程与目标进程位数相同。
inline bool InjectDllSameArch(DWORD pid, const std::wstring& dllPath)
{
    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProc) {
        InjLog(L"OpenProcess失败 pid=" + std::to_wstring(pid) + L" err=" + std::to_wstring(GetLastError()));
        return false;
    }

    // 已经注入过就不用再来一次，避免重复 LoadLibrary
    if (IsModuleLoadedInProcess(pid, dllPath)) {
        CloseHandle(hProc);
        return true;
    }

    SIZE_T sz = (dllPath.size() + 1) * sizeof(wchar_t);
    LPVOID remoteMem = VirtualAllocEx(hProc, nullptr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        InjLog(L"VirtualAllocEx失败 pid=" + std::to_wstring(pid) + L" err=" + std::to_wstring(GetLastError()));
        CloseHandle(hProc);
        return false;
    }

    if (!WriteProcessMemory(hProc, remoteMem, dllPath.c_str(), sz, nullptr)) {
        InjLog(L"WriteProcessMemory失败 pid=" + std::to_wstring(pid) + L" err=" + std::to_wstring(GetLastError()));
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    auto loadLibAddr = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"));
    if (!loadLibAddr) {
        InjLog(L"GetProcAddress(LoadLibraryW)失败 err=" + std::to_wstring(GetLastError()));
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, loadLibAddr, remoteMem, 0, nullptr);
    if (!hThread) {
        InjLog(L"CreateRemoteThread失败 pid=" + std::to_wstring(pid) + L" err=" + std::to_wstring(GetLastError()));
        VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    DWORD waitResult = WaitForSingleObject(hThread, 5000);
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode); // 仅作调试参考，不作为成败判据（见上面注释）
    CloseHandle(hThread);

    // 远线程已经执行完/等待结束，此时释放路径字符串占用的远端内存是安全的
    VirtualFreeEx(hProc, remoteMem, 0, MEM_RELEASE);

    if (waitResult != WAIT_OBJECT_0) {
        InjLog(L"远线程5秒内未结束（可能被目标进程挂起/加载器死锁）pid=" + std::to_wstring(pid));
        CloseHandle(hProc);
        return false;
    }

    InjLog(L"远线程已退出 pid=" + std::to_wstring(pid) + L" 线程退出码(仅参考)=0x" + std::to_wstring(exitCode));

    // 唯一权威判据
    bool loaded = IsModuleLoadedInProcess(pid, dllPath);
    if (!loaded) {
        InjLog(L"警告：远线程执行完毕，但目标进程模块表中未发现该DLL，判定注入失败 pid=" + std::to_wstring(pid));
    }
    CloseHandle(hProc);
    return loaded;
}