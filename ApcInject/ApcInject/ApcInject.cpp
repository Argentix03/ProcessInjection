#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <vector>

using namespace std;

int Error(const char* msg) {
	printf("%s (%u)\n", msg, GetLastError());
	return 1;
}

vector<DWORD> GetProcessThreads(DWORD pid) {
	vector<DWORD> tids;

	auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return tids;

	THREADENTRY32 te = { sizeof(te) };
	if (Thread32First(hSnapshot, &te)) {
		do {
			if (te.th32OwnerProcessID == pid) {
				tids.push_back(te.th32ThreadID);
			}
		} while (Thread32Next(hSnapshot, &te));
	}

	CloseHandle(hSnapshot);
	return tids;
}

int main(int argc, const char** argv) {
	if (argc < 3) {
		printf("Usage: ApcInject <pid> <dll path>\n");
		return 0;
	}

	int pid = atoi(argv[1]);

	HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
	if (!hProcess)
		return Error("Error opening process");

	void* buffer = VirtualAllocEx(hProcess, nullptr, 1 << 12, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!buffer)
		return Error("failed to allocate memory in process");

	if (!WriteProcessMemory(hProcess, buffer, argv[2], strlen(argv[2]), nullptr))
		return Error("failed to write memory");

	auto tids = GetProcessThreads(pid);
	if (tids.empty()) 
		return Error("failed to locate threads in process\n");

	for (const DWORD tid : tids) {
		HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
		if (hThread) {
			QueueUserAPC((PAPCFUNC)GetProcAddress(GetModuleHandle(L"kernel32"), "LoadLibraryA"), hThread, (ULONG_PTR)buffer);
			CloseHandle(hThread);
		}
	}
	printf("APC queued\n");

	CloseHandle(hProcess);

	return 0;
}
