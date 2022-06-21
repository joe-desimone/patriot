#include <windows.h>
#include <TlHelp32.h>
#include <stdio.h>

char PATRIOT_VERSION[] = "v0.2";

void* memmem(const void* haystack, size_t haystack_len,
	const void* const needle, const size_t needle_len)
{
	// https://stackoverflow.com/questions/52988769/writing-own-memmem-for-windows
	if (haystack == NULL) return NULL; // or assert(haystack != NULL);
	if (haystack_len == 0) return NULL;
	if (needle == NULL) return NULL; // or assert(needle != NULL);
	if (needle_len == 0) return NULL;

	for (const char* h = (const char*)haystack;
		haystack_len >= needle_len;
		++h, --haystack_len) {
		if (!memcmp(h, needle, needle_len)) {
			return (void*)h;
		}
	}
	return NULL;
}

bool FindTimerCallback(void* pBuf, SIZE_T szBuf, const wchar_t * dllName, const char * functionName)
{
	if (szBuf < 24)
	{
		return false;
	}

	void* pFunction = GetProcAddress(GetModuleHandle(dllName), functionName);
	char search[3 * 8] = {0};
	DWORD i = 0;

	memcpy(&search[i], "\x00\x00\x00\x00\x00\x00\x00\x00", 8);
	i += 8;
	memcpy(&search[i], "\x20\x00\x00\x00\x00\x00\x00\x00", 8);
	i += 8;
	memcpy(&search[i], &pFunction, 8);
	i += 8;
	if (memmem(pBuf, szBuf, search, i))
	{
		return true;
	}

	return false;

}

void * ScanProc(DWORD pid)
{
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (0 == hProcess)
	{
		return 0;
	}

	MEMORY_BASIC_INFORMATION mbi = { 0 };
	DWORD_PTR pMem = 0;
	while (true)
	{
		void* pBuf = 0;
		SIZE_T stRead = 0;
		MEMORY_BASIC_INFORMATION mbi = { 0 };
		if (0 == VirtualQueryEx(
			hProcess, (void*)pMem, &mbi, sizeof(mbi)))
		{
			return 0;
		}

		pMem += mbi.RegionSize;

		if (mbi.State != MEM_COMMIT || mbi.Protect != PAGE_READWRITE 
			|| mbi.RegionSize > 1024*1024*50
			|| mbi.Type != MEM_PRIVATE)
		{
			continue;
		}

		pBuf = malloc(mbi.RegionSize);

		if (!ReadProcessMemory(hProcess, mbi.BaseAddress, pBuf, mbi.RegionSize, &stRead))
		{
			free(pBuf);
			continue;
		}

		//printf("Scanning pid: %d, region: %p\n", pid, mbi.BaseAddress);

		if (FindTimerCallback(pBuf, mbi.RegionSize, L"ntdll.dll", "NtContinue") ||
			FindTimerCallback(pBuf, mbi.RegionSize, L"ntdll.dll", "RtlRestoreContext"))
		{
			free(pBuf);
			return mbi.BaseAddress;
		}

		free(pBuf);
		
	}
	return 0;

}

void EnumProcess()
{
	HANDLE hSnap = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 proc32;

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		goto Cleanup;
	}

	proc32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hSnap, &proc32))
	{
		goto Cleanup;
	}

	do
	{
		if (GetCurrentProcessId() == proc32.th32ProcessID)
			continue;

		void * pRegion = ScanProc(proc32.th32ProcessID);
		if (pRegion)
		{
			printf("[!] Suspicious timer found in process: %ws, pid: %d, region: %p\n", 
				proc32.szExeFile, proc32.th32ProcessID, pRegion);
		}
	} while ((Process32Next(hSnap, &proc32)) == TRUE);

Cleanup:

	if(hSnap != INVALID_HANDLE_VALUE)
		CloseHandle(hSnap);

	return;
}

int main()
{
	printf("Patriot memory scanner %s\n", PATRIOT_VERSION);
	printf("[+] Scanning..\n");
	EnumProcess();
	printf("[+] Scan complete.\n");
}

