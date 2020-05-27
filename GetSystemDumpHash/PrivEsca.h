#include "pch.h"
BOOL SePrivTokenrivilege(
    HANDLE hToken,
    LPCTSTR lpszPrivilege,
    BOOL bEnablePrivilege
);
DWORD FindProcessPID(const wchar_t* ProcessName);
BOOL TokenManipulationRestart();
BOOL BypassUacRestart(void);
BOOL TokenManipulationRestart();

