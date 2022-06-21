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

bool inline VirtualProtectFunction(void** functions, int count, DWORD64 function)
{
    for (int i = 0; i < count; i++)
    {
        if (functions[i] == (void*)function)
        {
            return true;
        }
    }

    return false;
}
bool inline
IsExecuteSet(DWORD protect)
{
    if ((protect == PAGE_EXECUTE) || (protect == PAGE_EXECUTE_READ) ||
        (protect == PAGE_EXECUTE_READWRITE) || (protect == PAGE_EXECUTE_WRITECOPY))
    {
        return true;
    }

    return false;
}

bool FindSuspiciousContext(DWORD pid, wchar_t * exeName, void* pBuf, SIZE_T szBuf)
{
    if (szBuf < sizeof(CONTEXT))
    {
        return false;
    }

    CONTEXT * pCtx;

    void* functions[10];
    functions[0] = GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtProtectVirtualMemory");
    functions[1] = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "VirtualProtect");
    functions[2] = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "VirtualProtectEx");
    functions[3] = GetProcAddress(GetModuleHandle(L"kernelbase.dll"), "VirtualProtect");
    functions[4] = GetProcAddress(GetModuleHandle(L"kernelbase.dll"), "VirtualProtectEx");
    int count = 5;

    for (int i = 0; i < szBuf - sizeof(CONTEXT); i += 8)
    {
        char* pcBuf = (char*)pBuf;
        pCtx = (CONTEXT*)&pcBuf[i];
        if ((pCtx->ContextFlags & CONTEXT_CONTROL) &&
            VirtualProtectFunction(functions, count, pCtx->Rip) &&
            (IsExecuteSet(pCtx->R8) || IsExecuteSet(pCtx->R9))
            )
        {
            DWORD64 target = 0;
            if (pCtx->Rcx == (DWORD64)-1)
                target = pCtx->Rdx;
            else
                target = pCtx->Rcx;

            printf("[!] Suspicious context found in PID: %d, Process: %ws, Target memory: %llx\n", pid, exeName, target);
            //printf("Parameters:\n");
            //printf("RIP: %llx\n", pCtx->Rip);
            //printf("RCX: %llx\n", pCtx->Rcx);
            //printf("RDX: %llx\n", pCtx->Rdx);
            //printf("R8: %llx\n", pCtx->R8);
            //printf("R9: %llx\n", pCtx->R9);
        }
    }
    return false;
}

void * ScanProc(DWORD pid, wchar_t * exeName)
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
        FindSuspiciousContext(pid, exeName, pBuf, mbi.RegionSize);

        if (FindTimerCallback(pBuf, mbi.RegionSize, L"ntdll.dll", "NtContinue") ||
            FindTimerCallback(pBuf, mbi.RegionSize, L"ntdll.dll", "RtlRestoreContext")
            )
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

        void * pRegion = ScanProc(proc32.th32ProcessID, proc32.szExeFile);
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

