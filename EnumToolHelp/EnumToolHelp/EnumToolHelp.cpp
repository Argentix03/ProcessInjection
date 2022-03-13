#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

int Error(const char* msg) {
    printf("%s (%u)", msg, GetLastError());
    return 1;
}

int main()
{
    //enum processes
    printf("Enumerating Processes\n");
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return Error("Failed to create snapshot");

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (!Process32First(hSnapshot, &pe))
        return Error("Failed in Process32First");

    do {
        printf("Name: %ws\tPID: %6u\tPPID: %6u\tThreads: %3u\n",
            pe.szExeFile, pe.th32ProcessID, pe.th32ParentProcessID, pe.cntThreads);
    } while (Process32Next(hSnapshot, &pe));

    CloseHandle(hSnapshot);

    //enum handles
    printf("Enumerating Modules\n");
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return Error("Failed to create snapshot");
    
    MODULEENTRY32 me;
    me.dwSize = sizeof(MODULEENTRY32);
    if (!Module32First(hSnapshot, &me))
        return Error("Failed to in Module32First");
    do {
        printf("Name: %ws\texe\\dll: %ws\Base Address: %6u\tSize: %6u\tPID: %6u\n",
            me.szModule, me.szExePath, me.modBaseSize, me.modBaseAddr, me.th32ProcessID);
    } while (Module32Next(hSnapshot, &me));

    CloseHandle(hSnapshot);

    return 0;
}

