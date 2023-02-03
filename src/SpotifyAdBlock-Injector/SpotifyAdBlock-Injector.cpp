#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <wtsapi32.h>
#include <ctype.h>
#include <conio.h>

#pragma warning(disable : 4996)
#pragma comment(lib, "Wtsapi32.lib")

bool InjectDLL(HANDLE procHandle, char* dllPath) 
{
    void* remoteBuffer = VirtualAllocEx(procHandle, NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!WriteProcessMemory(procHandle, remoteBuffer, dllPath, strlen(dllPath) + 1, NULL))
    {
        std::cout << "INJECTING FAILED: Unable to write to the allocated buffer!\n";
        return false;
    }

    HANDLE remoteThreadHandle = CreateRemoteThread(procHandle, NULL, NULL, 
        (LPTHREAD_START_ROUTINE)LoadLibraryA, remoteBuffer, NULL, NULL);
    VirtualFree(remoteBuffer, strlen(dllPath) + 1, MEM_RELEASE);

    if (!remoteThreadHandle) 
    {
        std::cout << "INJECTING FAILED: Unable to create a remote thread!\n";
        return false;
    }

    CloseHandle(remoteThreadHandle);

    return true;
}

std::vector<DWORD> GetProcesses(char* name)
{
    WTS_PROCESS_INFO* pWPIs = NULL;
    DWORD dwProcCount = 0;
    std::vector<DWORD> procs;

    if (WTSEnumerateProcesses(WTS_CURRENT_SERVER_HANDLE, NULL, 1, &pWPIs, &dwProcCount))
    {
        for (DWORD i = 0; i < dwProcCount; i++)
        {
            WTS_PROCESS_INFO proc = pWPIs[i];
            LPWSTR procName = proc.pProcessName;
            DWORD procID = proc.ProcessId;

            wchar_t* nameW = new wchar_t[strlen(name) + 1];
            mbstowcs(nameW, name, strlen(name) + 1);

            if (wcscmp(_wcslwr(procName), nameW) == 0)
            {
                procs.push_back(procID);
            }
        }
    }

    if (pWPIs)
    {
        WTSFreeMemory(pWPIs);
        pWPIs = NULL;
    }

    return procs;
}

int main(int argc, char** argv)
{
    char* depPath = argv[1];
    char* dllPath = argv[2];
    char* procName = argv[3];

    if (argc < 4) 
    {
        std::cout << "Usage: " << argv[0] << " <dependency path> <DLL path> <process name>\n";
        return 1;
    }

    std::cout << "Dependency Path: " << depPath << "\n";
    std::cout << "DLL Path: " << dllPath << "\n";
    std::cout << "Process Name: " << procName << "\n";

    if (GetFileAttributesA(depPath) == INVALID_FILE_ATTRIBUTES)
    {
        std::cerr << "Unable to find " << dllPath << "!\n";
        return 1;
    }

    if (GetFileAttributesA(dllPath) == INVALID_FILE_ATTRIBUTES) 
    {
        std::cerr << "Unable to find " << dllPath << "!\n";
        return 1;
    }

    std::vector<DWORD> procs = GetProcesses(procName);
    std::cout << "Found " << procs.capacity() << " processes\n";

    for (size_t procIndex = 0; procIndex < procs.capacity(); procIndex++)
    {
        DWORD proc = procs[procIndex];
        HANDLE procHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, proc);

        if (procHandle == NULL)
        {
            std::cerr << "Unable to open process " << proc << "!\n";
            continue;
        }

        bool depInjectStatus = InjectDLL(procHandle, depPath);
        bool dllInjectStatus = InjectDLL(procHandle, dllPath);
        CloseHandle(procHandle);

        if (!depInjectStatus || !dllInjectStatus)
        {
            std::cerr << "Unable to inject the DLLs into the process " << proc << "!\n";
            continue;
        }

        std::cout << "Injected into process " << proc << "!\n";
    }

    std::cout << "Press any key to continue...\n";
    int chr = _getch();
    chr = 0;

    return 0;
}
