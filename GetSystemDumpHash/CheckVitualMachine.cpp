#include "pch.h"

VOID NTAPI TlsCallBackCheckDbugger(PVOID DllHandle, DWORD dwReason, PVOID Reserved)
{

    if (dwReason == DLL_PROCESS_ATTACH)
    {
        //Check Debugger
        if (IsDebuggerPresent()) TerminateProcess(GetCurrentProcess(), NULL);

        BOOL isDebugger = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugger);
        if (isDebugger) TerminateProcess(GetCurrentProcess(), NULL);

        PDWORD pFlags = (PDWORD)((PBYTE)GetProcessHeap() + 0x70);
        PDWORD pForceFlags = (PDWORD)((PBYTE)GetProcessHeap() + 0x74);
        if (*pFlags ^ HEAP_GROWABLE || *pForceFlags != 0) TerminateProcess(GetCurrentProcess(), NULL);


        //Check is VirtualMachine
        MEMORYSTATUSEX mStatus;
        mStatus.dwLength = sizeof(mStatus);
        GlobalMemoryStatusEx(&mStatus);
        DWORD RAMMB = mStatus.ullTotalPhys / 1024 / 1024;
        if (RAMMB < 2048)  TerminateProcess(GetCurrentProcess(), NULL);

        HANDLE hDevice = CreateFileW(L"\\.\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        DISK_GEOMETRY pDiskGeometry;
        DWORD bytesReturned;
        DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pDiskGeometry, sizeof(pDiskGeometry), &bytesReturned, (LPOVERLAPPED)NULL);
        DWORD diskSizeGB;
        diskSizeGB = pDiskGeometry.Cylinders.QuadPart * (ULONG)pDiskGeometry.TracksPerCylinder * (ULONG)pDiskGeometry.SectorsPerTrack * (ULONG)pDiskGeometry.BytesPerSector / 1024 / 1024 / 1024;
        if (diskSizeGB < 100) TerminateProcess(GetCurrentProcess(), NULL);

    }

}
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback") 



EXTERN_C
#pragma const_seg (".CRT$XLB")
const PIMAGE_TLS_CALLBACK _tls_callback = TlsCallBackCheckDbugger;
#pragma const_seg ()