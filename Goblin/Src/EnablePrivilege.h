#pragma once

#include <Windows.h>

// Constants
// ------------------------------------------------------------------------

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define STATUS_SUCCESS 0

// Function prototypes
// ------------------------------------------------------------------------

typedef NTSTATUS(NTAPI* _NtOpenProcessToken)(
	IN HANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	OUT PHANDLE TokenHandle
	);

typedef NTSTATUS(NTAPI* _NtAdjustPrivilegesToken)(
	IN HANDLE TokenHandle,
	IN BOOLEAN DisableAllPrivileges,
	IN PTOKEN_PRIVILEGES TokenPrivileges,
	IN ULONG PreviousPrivilegesLength,
	OUT PTOKEN_PRIVILEGES PreviousPrivileges OPTIONAL,
	OUT PULONG RequiredLength OPTIONAL
	);

typedef BOOL (WINAPI* _LookupPrivilegeValueA)(
	LPCSTR lpSystemName,
    LPCSTR lpName,
    PLUID  lpLuid
    );

// To enable a privilege by its constant
// ------------------------------------------------------------------------

BOOL enable_privilege(LPCTSTR name) {
    // Dynamically resolve the API functions from Ntdll.dll
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

	_NtOpenProcessToken NtOpenProcessToken = (_NtOpenProcessToken)GetProcAddress(ntdll, "NtOpenProcessToken");
	if (NtOpenProcessToken == NULL) {
		return FALSE;
	}

	_NtAdjustPrivilegesToken NtAdjustPrivilegesToken = (_NtAdjustPrivilegesToken)GetProcAddress(ntdll, "NtAdjustPrivilegesToken");
	if (NtAdjustPrivilegesToken == NULL) {
		return FALSE;
	}

	// Dynamically resolve the API function from Advapi32.dll
	HMODULE advapi32 = LoadLibraryA("Advapi32.dll");

	_LookupPrivilegeValueA LookupPrivilegeValueA = (_LookupPrivilegeValueA)GetProcAddress(advapi32, "LookupPrivilegeValueA");
	if (LookupPrivilegeValueA == NULL)
		return FALSE;

	// Init local variables
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES TokenPrivileges = { 0 };

    // Enable the privilege
	NTSTATUS status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	if(!LookupPrivilegeValueA(NULL, name, &luid)) {
		CloseHandle(hToken);
		return FALSE;
	}

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Luid = luid;
	TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	status = NtAdjustPrivilegesToken(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	if (status != STATUS_SUCCESS) {
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);
	return TRUE;
}
