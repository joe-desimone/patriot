/*
 * Patriot memory scanner
 * Copyright 2022 Joe Desimone. All rights reserved.
 * Contact: @dez_
 */

#pragma once
// clang-format off
#include <windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <stdio.h>

// clang-format on

#include <format>
#include <memory>
#include <string>
#include <vector>

#include "patriot.h"

enum LOG_LEVEL
{
    debug,
    info,
    warning,
    error
};

static inline bool _InvalidPtr(const char* pBuf, SIZE_T bufSz, const char* pData, SIZE_T dataSz)
{
    if (pData < pBuf)
    {
        return true;
    }

    if ((pData + dataSz) > (pBuf + bufSz))
    {
        return true;
    }

    if ((pBuf + bufSz) < pBuf)
    {
        return true;
    }

    if ((pData + dataSz) < pData)
    {
        return true;
    }

    return false;
}

#define InvalidPtr(pBuf, bufSz, pData, dataSz) \
    _InvalidPtr((const char*)(pBuf), (SIZE_T)(bufSz), (const char*)(pData), (SIZE_T)(dataSz))

static bool inline VirtualProtectFunction(void** functions, int count, DWORD64 function)
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

static bool inline IsExecuteSet(DWORD protect)
{
    if( protect & 0xF0 )
    {
        return true;
    }
    return false;
}

void Log(LOG_LEVEL level, const char* fmt, ...);
bool UnsharedSize(HANDLE hProcess, void* regionBase, SIZE_T regionSize, SIZE_T& unsharedSized);

typedef struct Module
{
    DWORD_PTR moduleBase;
    SIZE_T moduleSize;
    std::wstring modulePathNt;
    std::wstring modulePathDos;
    DWORD getPathError;
    Module() : moduleBase(0), moduleSize(0), getPathError(0) { modulePathNt.resize(MAX_PATH); }
} Module;
typedef std::shared_ptr<Module> SPModule;
typedef std::vector<SPModule> ModuleList;

typedef std::vector<std::unique_ptr<MEMORY_BASIC_INFORMATION>> MemoryMap;

typedef struct Process
{
    DWORD pid;
    std::wstring processName;
    BOOL bElevated;
    HANDLE hProcess;
    MemoryMap memoryMap;
    ModuleList moduleList;
    Process(DWORD p, std::wstring n)
    {
        pid         = p;
        processName = n;
        bElevated   = FALSE;
        hProcess    = 0;
    }
} Process;
typedef std::vector<Process> ProcessList;

typedef struct Finding
{
    DWORD pid;
    std::wstring processName;
    SPModule moduleInfo;
    MEMORY_BASIC_INFORMATION mbi;
    std::string type;
    std::string details;
    std::string level;
    Finding() : pid(0) {}
} Finding;
typedef std::unique_ptr<Finding> UPFinding;
extern std::vector<UPFinding> Findings;
#define DeleteHandle(x)                 \
    if (x && x != INVALID_HANDLE_VALUE) \
    {                                   \
        CloseHandle(x);                 \
        x = 0;                          \
    }

#define CleanupError() \
    status = false;    \
    goto Cleanup;

#define CleanupSuccess() \
    status = true;       \
    goto Cleanup;

class PEFile
{
   private:
   public:
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS64 ntHeader;
    IMAGE_NT_HEADERS32* pNtHeader32;
    std::string headerBuf;
    bool bHeaderLoaded;
    bool bDotNet;
    std::wstring processName;
    DWORD pid;
    SPModule moduleInfo;
    PEFile();

    bool LoadHeaderFromDisk(const std::wstring filePathNt);
    bool LoadHeaderFromMemory(HANDLE hProcess, DWORD_PTR moduleBase);
    bool ParseHeader();
    static bool ValidateIntegrity(PEFile& peDisk, PEFile& peMem, Process& process);
    void NewFinding(const std::string level, const std::string subtype, const std::string details);
};
