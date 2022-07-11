#pragma once
#include <windows.h>

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _IO_STATUS_BLOCK
{
    union
    {
        LONG Status;
        PVOID Pointer;
    };
    ULONG Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;


typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef ULONG(__stdcall* _NtCreateFile)(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength
    );

typedef void(__stdcall* _RtlInitUnicodeString)(
    PUNICODE_STRING DestinationString,
    PCWSTR          SourceString
);

#define InitializeObjectAttributes( p, n, a, r, s ) { \
(p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
(p)->RootDirectory = r;                             \
(p)->Attributes = a;                                \
(p)->ObjectName = n;                                \
(p)->SecurityDescriptor = s;                        \
(p)->SecurityQualityOfService = NULL;               \
}

#define OBJ_CASE_INSENSITIVE  0x00000040L
#define FILE_NON_DIRECTORY_FILE  0x00000040
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define FILE_OPEN   0x00000001L