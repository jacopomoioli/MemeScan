#include <Windows.h>
#include <stdio.h>
#include <wtsapi32.h>

#pragma comment(lib, "Wtsapi32.lib")

#define PAGE_PROTECTION_FLAGS (PAGE_NOACCESS | PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY )

char IsExecutable(DWORD protect){
    switch(protect & PAGE_PROTECTION_FLAGS){
        case PAGE_EXECUTE:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return 1;
        default:
            return 0;
    }
}

char IsWritable(DWORD protect){
    switch(protect & PAGE_PROTECTION_FLAGS){
        case PAGE_READWRITE:
        case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return 1;
        default:
            return 0;
    }
}

/* Convert memory protection constants to string */
const char* ProtectionToString(DWORD protect){
	switch (protect & 0xFF){
        case PAGE_NOACCESS:          return "####";
        case PAGE_READONLY:          return "R###";
        case PAGE_READWRITE:         return "RW##";
        case PAGE_WRITECOPY:         return "#W#C";
        case PAGE_EXECUTE:           return "##X#";
        case PAGE_EXECUTE_READ:      return "R#X#";
        case PAGE_EXECUTE_READWRITE: return "RWX#";
        case PAGE_EXECUTE_WRITECOPY: return "#WXC";
        default:                     return "????";
	}
}

/* Convert page state constants to string */
const char* StateToString(DWORD state){
	switch (state){
        case MEM_COMMIT:  return "MEM_COMMIT";
        case MEM_RESERVE: return "MEM_RESERVE";
        case MEM_FREE:    return "MEM_FREE";
        default:          return "UNKNOWN";
	}
}


/* Scan the process memory and print the pages with suspicious protection attributes */
void ScanProcessMemory(HANDLE processHandle, DWORD pid, LPSTR processName) {
	LPVOID address = 0;
	MEMORY_BASIC_INFORMATION mbi;

	while (VirtualQueryEx(
		processHandle,
		address,
		&mbi,
		sizeof(mbi)
	)) {
		// Skip useless stuff
        if (!IsExecutable(mbi.Protect) && !IsWritable(mbi.Protect)) goto skip_to_next_page;


		printf(
			"[!] %s (PID %d): \n\t%s @ 0x%p (%d bytes)\n\tOriginal protection: %s\n", 
			processName, 
			pid, 
			ProtectionToString(mbi.Protect), 
			address, 
			mbi.RegionSize,
			ProtectionToString(mbi.AllocationProtect)
		);

	skip_to_next_page:
		address = (LPVOID)((BYTE*)mbi.BaseAddress + mbi.RegionSize);
	}
}


int main(int argc, char** argv) {
	DWORD pid = 0;
	HANDLE processHandle;

	// if a PID is specified, scan only that process
	if (argc == 2) {
		pid = atoi(argv[1]);

		processHandle = OpenProcess(
			PROCESS_QUERY_INFORMATION,
			FALSE,
			pid
		);
		if (!processHandle) {
			printf("Error while opening process %d. Quitting\n", pid);
			return 1;
		}

		ScanProcessMemory(processHandle, pid, "");
		return 0;
	}

	// If no PID is specified, system-wide memory scanning
	DWORD processCount;
	WTS_PROCESS_INFOA* processesInfo;

	// Enumerate using WTSEnumerateProcesses.
	// Kinda weird because the api is made for remote desktop, but can be used for local process enumeration.
	// I like it more than CreateToolhelp32Snapshot.
	if (!WTSEnumerateProcessesA(WTS_CURRENT_SERVER_HANDLE, 0, 1, &processesInfo, &processCount)) {
		printf("Error while enumerating processes. Quitting\n");
		return 1;
	}

	for (DWORD i = 0; i < processCount; i++) {
		processHandle = OpenProcess(
			PROCESS_QUERY_LIMITED_INFORMATION,
			FALSE,
			processesInfo[i].ProcessId
		);
		if (!processHandle) continue;

		ScanProcessMemory(processHandle, processesInfo[i].ProcessId, processesInfo[i].pProcessName);

        CloseHandle(processHandle);
	}

    WTSFreeMemory(&processesInfo);

	return 0;

}
