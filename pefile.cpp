/*
 * Patriot memory scanner
 * Copyright 2022 Joe Desimone. All rights reserved.
 * Contact: @dez_
 */

#include "nt.h"
#include "patriot.h"

// Constructor
PEFile::PEFile()
{
    ZeroMemory(&dosHeader, sizeof(dosHeader));
    ZeroMemory(&ntHeader, sizeof(ntHeader));
    bHeaderLoaded = false;
    bDotNet       = false;
    pNtHeader32   = 0;
    pid           = 0;
}

void PEFile::NewFinding(const std::string level, const std::string subtype,
                        const std::string details)
{
    auto finding = std::make_unique<Finding>();

    finding->pid         = pid;
    finding->processName = processName;
    finding->level       = level;
    finding->type        = "peIntegrity";
    finding->details     = details;
    finding->moduleInfo  = moduleInfo;

    Findings.push_back(std::move(finding));
}

bool PEFile::ParseHeader()
{
    // ToDo errors here should be findings
    bool status                         = true;
    char* pBuf                          = &headerBuf[0];
    SIZE_T bufSz                        = headerBuf.size();
    IMAGE_NT_HEADERS64* pNtHeader       = 0;
    IMAGE_DATA_DIRECTORY* pDirectoryCOM = 0;
    IMAGE_SECTION_HEADER* pSection      = 0;

    if (headerBuf.size() < sizeof(dosHeader))
    {
        Log(warning, "[!] Invalid headerBuf size\n");
        CleanupError();
    }

    memcpy(&dosHeader, &headerBuf[0], sizeof(dosHeader));

    pNtHeader = (IMAGE_NT_HEADERS64*)(pBuf + dosHeader.e_lfanew);
    if (InvalidPtr(pBuf, bufSz, pNtHeader, sizeof(IMAGE_NT_HEADERS64)))
    {
        NewFinding("suspect", "ntHeaderPtr",
                   std::format("Invalid NtHeader Ptr {:016x}", (DWORD_PTR)pNtHeader));
        CleanupError();
    }

    memcpy(&ntHeader, pNtHeader, sizeof(IMAGE_NT_HEADERS64));

    if (IMAGE_FILE_MACHINE_I386 == ntHeader.FileHeader.Machine)
    {
        pNtHeader32 = (IMAGE_NT_HEADERS32*)&ntHeader;
        pDirectoryCOM =
            &pNtHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
        if (pDirectoryCOM->VirtualAddress)
        {
            bDotNet = true;
        }
    }
    else
    {
        pDirectoryCOM =
            &ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
        if (pDirectoryCOM->VirtualAddress)
        {
            bDotNet = true;
        }
    }

    pSection = IMAGE_FIRST_SECTION(pNtHeader);

    if (InvalidPtr(pBuf, bufSz, pSection, sizeof(*pSection) * ntHeader.FileHeader.NumberOfSections))
    {
        NewFinding("suspect", "ntSectionPtr",
                   std::format("Invalid section header pointer {:016x} * {}", (DWORD_PTR)pSection,
                               ntHeader.FileHeader.NumberOfSections));
        CleanupError();
    }

    for (int i = 0; i < ntHeader.FileHeader.NumberOfSections; i++)
    {
        if (pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE & IMAGE_SCN_MEM_WRITE)
        {
            NewFinding(
                "suspect", "rwxCodeSection",
                std::format("RWX Code section: {}{}{}{}{}", pSection->Name[0], pSection->Name[1],
                            pSection->Name[2], pSection->Name[3], pSection->Name[4]));
        }
        pSection++;
    }

Cleanup:
    return status;
}

bool PEFile::LoadHeaderFromDisk(const std::wstring filePathNt)
{
    bool status = true;

    _NtCreateFile NtCreateFile =
        (_NtCreateFile)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateFile");
    _RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(
        GetModuleHandle(L"ntdll.dll"), "RtlInitUnicodeString");
    HANDLE hFile = 0;
    DWORD dwRead = 0;
    UNICODE_STRING filePath;
    OBJECT_ATTRIBUTES oa = {0};
    IO_STATUS_BLOCK iosb = {0};
    RtlInitUnicodeString(&filePath, filePathNt.c_str());
    InitializeObjectAttributes(&oa, &filePath, OBJ_CASE_INSENSITIVE, 0, 0);

    LONG retVal = 0;

    if (bHeaderLoaded)
    {
        CleanupSuccess();
    }

    retVal =
        NtCreateFile(&hFile, FILE_GENERIC_READ | SYNCHRONIZE, &oa, &iosb, 0, 0, FILE_SHARE_READ,
                     FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);
    if (retVal < 0)
    {
        Log(warning, "[!] Error opening: %ws. ntstatus: %x\n", filePathNt.c_str(), retVal);
        CleanupError();
    }

    headerBuf.resize(0x1000);

    if (!ReadFile(hFile, &headerBuf[0], (DWORD)headerBuf.size(), &dwRead, 0) ||
        dwRead != headerBuf.size())
    {
        Log(warning, "[!] Error reading: %ws. last error: %d\n", filePathNt.c_str(),
            GetLastError());
        CleanupError();
    }

    bHeaderLoaded = true;

    status = ParseHeader();

Cleanup:
    DeleteHandle(hFile);
    return status;
}

bool PEFile::LoadHeaderFromMemory(HANDLE hProcess, DWORD_PTR moduleBase)
{
    bool status      = true;
    SIZE_T bytesRead = 0;

    if (bHeaderLoaded)
    {
        CleanupSuccess();
    }

    headerBuf.resize(0x1000);

    if (!ReadProcessMemory(hProcess, (void*)moduleBase, &headerBuf[0], headerBuf.size(),
                           &bytesRead) ||
        bytesRead != headerBuf.size())
    {
        Log(warning, "[!] Error reading module header: %llx, last error: %d", moduleBase,
            GetLastError());
        CleanupError();
    }

    bHeaderLoaded = true;

    status = ParseHeader();

Cleanup:
    return status;
}

void UpConvertNtHeader(IMAGE_NT_HEADERS64& ntHeader)
{
    // Make a backup of original values;
    IMAGE_NT_HEADERS32 ntHeaderOriginal;
    memcpy(&ntHeaderOriginal, &ntHeader, sizeof(ntHeaderOriginal));

    // Update optional header size
    ntHeader.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    // Change magic to PE32+
    ntHeader.OptionalHeader.Magic = 0x20b;

    // Up convert the on-disk values to match the expected in-memory values
    ntHeader.OptionalHeader.SectionAlignment = ntHeaderOriginal.OptionalHeader.SectionAlignment;
    ntHeader.OptionalHeader.FileAlignment    = ntHeaderOriginal.OptionalHeader.FileAlignment;
    ntHeader.OptionalHeader.MajorOperatingSystemVersion =
        ntHeaderOriginal.OptionalHeader.MajorOperatingSystemVersion;
    ntHeader.OptionalHeader.MinorOperatingSystemVersion =
        ntHeaderOriginal.OptionalHeader.MinorOperatingSystemVersion;
    ntHeader.OptionalHeader.MajorImageVersion = ntHeaderOriginal.OptionalHeader.MajorImageVersion;
    ntHeader.OptionalHeader.MinorImageVersion = ntHeaderOriginal.OptionalHeader.MinorImageVersion;
    ntHeader.OptionalHeader.MajorSubsystemVersion =
        ntHeaderOriginal.OptionalHeader.MajorSubsystemVersion;
    ntHeader.OptionalHeader.MinorSubsystemVersion =
        ntHeaderOriginal.OptionalHeader.MinorSubsystemVersion;
    ntHeader.OptionalHeader.Win32VersionValue  = ntHeaderOriginal.OptionalHeader.Win32VersionValue;
    ntHeader.OptionalHeader.SizeOfImage        = ntHeaderOriginal.OptionalHeader.SizeOfImage;
    ntHeader.OptionalHeader.SizeOfHeaders      = ntHeaderOriginal.OptionalHeader.SizeOfHeaders;
    ntHeader.OptionalHeader.CheckSum           = ntHeaderOriginal.OptionalHeader.CheckSum;
    ntHeader.OptionalHeader.Subsystem          = ntHeaderOriginal.OptionalHeader.Subsystem;
    ntHeader.OptionalHeader.DllCharacteristics = ntHeaderOriginal.OptionalHeader.DllCharacteristics;
    ntHeader.OptionalHeader.SizeOfStackReserve = ntHeaderOriginal.OptionalHeader.SizeOfStackReserve;
    ntHeader.OptionalHeader.SizeOfStackCommit  = ntHeaderOriginal.OptionalHeader.SizeOfStackCommit;
    ntHeader.OptionalHeader.SizeOfHeapReserve  = ntHeaderOriginal.OptionalHeader.SizeOfHeapReserve;
    ntHeader.OptionalHeader.SizeOfHeapCommit   = ntHeaderOriginal.OptionalHeader.SizeOfHeapCommit;
    ntHeader.OptionalHeader.LoaderFlags        = ntHeaderOriginal.OptionalHeader.LoaderFlags;
    ntHeader.OptionalHeader.NumberOfRvaAndSizes =
        ntHeaderOriginal.OptionalHeader.NumberOfRvaAndSizes;
    memcpy(&ntHeader.OptionalHeader.DataDirectory, &ntHeaderOriginal.OptionalHeader.DataDirectory,
           sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
}

bool PEFile::ValidateIntegrity(PEFile& peDisk, PEFile& peMem, Process& process)
{
    bool status            = true;
    DWORD optionalHeaderSz = 0;
    bool bUpConverted      = false;

    if ((peDisk.dosHeader.e_magic != peMem.dosHeader.e_magic) ||
        (peDisk.dosHeader.e_cblp != peMem.dosHeader.e_cblp) ||
        (peDisk.dosHeader.e_cp != peMem.dosHeader.e_cp) ||
        (peDisk.dosHeader.e_cparhdr != peMem.dosHeader.e_cparhdr) ||
        (peDisk.dosHeader.e_sp != peMem.dosHeader.e_sp) ||
        (peDisk.dosHeader.e_lfarlc != peMem.dosHeader.e_lfarlc) ||
        (peDisk.dosHeader.e_lfanew != peMem.dosHeader.e_lfanew))
    {
        peMem.NewFinding("suspect", "mzHeader", "MZ Header tampered in memory");
        CleanupSuccess();
    }

    if (peDisk.bDotNet &&
        peDisk.ntHeader.FileHeader.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER32) &&
        peMem.ntHeader.FileHeader.SizeOfOptionalHeader == sizeof(IMAGE_OPTIONAL_HEADER64))
    {
        // .NET MSIL binaries up-convert from 32->64 in memory
        UpConvertNtHeader(peDisk.ntHeader);

        // Unclobber entry point
        peMem.ntHeader.OptionalHeader.AddressOfEntryPoint =
            peDisk.ntHeader.OptionalHeader.AddressOfEntryPoint;

        bUpConverted = true;
    }
    if ((peDisk.ntHeader.Signature != peMem.ntHeader.Signature) ||
        (memcmp(&peDisk.ntHeader.FileHeader, &peMem.ntHeader.FileHeader,
                sizeof(peDisk.ntHeader.FileHeader)) != 0))
    {
        peMem.NewFinding("suspect", "ntHeader", "PE Header tampered in memory");
        CleanupSuccess();
    }

    if ((IMAGE_FILE_MACHINE_I386 == peDisk.ntHeader.FileHeader.Machine) && (!bUpConverted))
    {
        // x86 image
        optionalHeaderSz = sizeof(IMAGE_OPTIONAL_HEADER32);
        IMAGE_OPTIONAL_HEADER32* pOptionalDisk =
            (IMAGE_OPTIONAL_HEADER32*)&peDisk.ntHeader.OptionalHeader;
        IMAGE_OPTIONAL_HEADER32* pOptionalMem =
            (IMAGE_OPTIONAL_HEADER32*)&peMem.ntHeader.OptionalHeader;
        pOptionalDisk->ImageBase = 0;
        pOptionalMem->ImageBase  = 0;
    }
    else
    {
        optionalHeaderSz                         = sizeof(IMAGE_OPTIONAL_HEADER64);
        peDisk.ntHeader.OptionalHeader.ImageBase = 0;
        peMem.ntHeader.OptionalHeader.ImageBase  = 0;
    }

    if (memcmp(&peDisk.ntHeader.OptionalHeader, &peMem.ntHeader.OptionalHeader, optionalHeaderSz) !=
        0)
    {
        peMem.NewFinding("suspect", "ntOptionalHeader", "NT Optional Header tampered in memory");
        CleanupSuccess();
    }

    // First, ensure everything mapped +X in memory is correlated with a +X PE section on disk
    for (auto it = process.memoryMap.begin(); it != process.memoryMap.end(); it++)
    {
        auto pMbi = it->get();
        if (pMbi->AllocationBase != (void*)peMem.moduleInfo->moduleBase ||
            !IsExecuteSet(pMbi->Protect))
        {
            continue;
        }

        Log(debug, "Module: %ws, +X Region: %p\n", peMem.moduleInfo->modulePathNt.c_str(),
            pMbi->BaseAddress);

        char* pBuf                     = &peMem.headerBuf[0];
        SIZE_T bufSz                   = peMem.headerBuf.size();
        IMAGE_NT_HEADERS64* pNtHeader  = (IMAGE_NT_HEADERS64*)(pBuf + peMem.dosHeader.e_lfanew);
        PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeader);
        bool bFoundSection             = false;
        DWORD totalSectionSize         = 0;
        SIZE_T attributedSize          = 0;
        SIZE_T unsharedSize            = 0;
        if (InvalidPtr(pBuf, bufSz, pSection,
                       sizeof(*pSection) * peMem.ntHeader.FileHeader.NumberOfSections))
        {
            peMem.NewFinding(
                "suspect", "ntSectionHeader",
                std::format("Invalid section header pointer", (DWORD_PTR)pMbi->BaseAddress));
            CleanupError();
        }

        for (int i = 0; i < peMem.ntHeader.FileHeader.NumberOfSections; i++, pSection++)
        {
            DWORD_PTR pSectionAddr = pSection->VirtualAddress + (DWORD_PTR)pMbi->AllocationBase;
            /*std::string characteristics;
            if (pSection->Characteristics & IMAGE_SCN_MEM_READ)
                characteristics += "R";
            if (pSection->Characteristics & IMAGE_SCN_MEM_WRITE)
                characteristics += "W";
            if (pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE)
                characteristics += "X";
            if (pSection->Characteristics & IMAGE_SCN_MEM_SHARED)
                characteristics += "S";
            if (pSection->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
                characteristics += "D";

            printf("Section: %c%c%c%c%c%c%c%c, Permissions: %s , Size: %x, Addr: %p, flags: %x\n",
                   pSection->Name[0], pSection->Name[1], pSection->Name[2], pSection->Name[3],
                   pSection->Name[4], pSection->Name[5], pSection->Name[6], pSection->Name[7],
                   characteristics.c_str(), pSection->Misc.VirtualSize, pSectionAddr,
                   pSection->Characteristics);*/

            if ((pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 &&
                strncmp("W64SVC", (const char*)&pSection->Name, 6) != 0 &&
                strncmp(".crthunk", (const char*)&pSection->Name, 8) != 0 &&
                strncmp(".oldntma", (const char*)&pSection->Name, 8) != 0)

            {
                // W64SVC section in wow64cpu.dll is read only on disk but RX in memory
                // Same for .crthunk and .oldntma in msedge_elf.dll
                // They should only be 0x200 in raw size
                continue;
            }

            DWORD alignedSize = pSection->Misc.VirtualSize;
            if (alignedSize % 0x1000)
            {
                alignedSize += 0x1000 - (alignedSize % 0x1000);
            }

            if ((((DWORD_PTR)pMbi->BaseAddress + attributedSize) < pSectionAddr) ||
                ((DWORD_PTR)pMbi->BaseAddress + attributedSize) > (pSectionAddr + alignedSize))
            {
                continue;
            }

            // How much fits into this section?
            attributedSize += min(alignedSize, pMbi->RegionSize);

            if (attributedSize == pMbi->RegionSize)
            {
                bFoundSection = true;
                break;
            }
        }

        if (!bFoundSection)
        {
            peMem.NewFinding(
                "suspect", "executableSections",
                std::format("Executable region {:016x} does not aligned with section header",
                            (DWORD_PTR)pMbi->BaseAddress));
        }

        if (UnsharedSize(process.hProcess, pMbi->BaseAddress, pMbi->RegionSize, unsharedSize) &&
            unsharedSize > 0x1000)
        {
            peMem.NewFinding("suspect", "modifiedCode",
                             std::format("Executable region {:016x} likely modified",
                                         (DWORD_PTR)pMbi->BaseAddress));
        }
    }

Cleanup:
    return status;
}
