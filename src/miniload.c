/*
 * miniload.c - Minimal PE loader for learning purposes.
 *
 * Supported: PE32+ (x64) executables, sections, DIR64 relocations, imports
 * by name/ordinal, .pdata registration and execution in a worker thread.
 *
 * Usage:
 *   miniload.exe <pe>
 */

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>

#pragma warning(disable: 4055 4113)

typedef struct {
    BYTE  *data;
    SIZE_T size;
} FILE_BUFFER;

typedef struct {
    BYTE  *base;
    SIZE_T size;
    PVOID  entry;
    DWORD  relocations;
    DWORD  imports;
    DWORD  pdata_entries;
} MAPPED_PE;

/* UNWIND_HISTORY_TABLE: not exposed by user-mode headers, but
 * RtlLookupFunctionEntry dereferences it (NULL crashes). */
typedef struct {
    DWORD64 image_base;
    PRUNTIME_FUNCTION function_entry;
} HISTORY_ENTRY;

typedef struct {
    DWORD count;
    BYTE  local_hint;
    BYTE  global_hint;
    BYTE  search;
    BYTE  once;
    DWORD64 low_address;
    DWORD64 high_address;
    HISTORY_ENTRY entries[12];
} HISTORY_TABLE;

typedef BOOLEAN (WINAPI *PFN_RTL_ADD_FUNCTION_TABLE)(PRUNTIME_FUNCTION, DWORD, DWORD64);
typedef PRUNTIME_FUNCTION (WINAPI *PFN_RTL_LOOKUP_FUNCTION_ENTRY)(DWORD64, PDWORD64, PVOID);
typedef int (WINAPI *PFN_ENTRY)(void);

static volatile LONG g_payload_exit = -1;

static VOID WINAPI ExitStub(UINT code)
{
    InterlockedExchange(&g_payload_exit, (LONG)code);
    ExitThread((DWORD)code);
}

static int ReadWholeFile(const char *path, FILE_BUFFER *out)
{
    FILE *f;
    long size;

    if (path == NULL || out == NULL) return 0;
    out->data = NULL;
    out->size = 0;

    f = fopen(path, "rb");
    if (f == NULL) return 0;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 0; }
    size = ftell(f);
    if (size <= 0 || size > 0x4000000) { fclose(f); return 0; }
    rewind(f);

    out->data = (BYTE *)malloc((SIZE_T)size);
    if (out->data == NULL) { fclose(f); return 0; }
    if (fread(out->data, 1, (SIZE_T)size, f) != (SIZE_T)size) {
        free(out->data);
        out->data = NULL;
        fclose(f);
        return 0;
    }
    fclose(f);
    out->size = (SIZE_T)size;
    return 1;
}

static int ApplyBaseRelocations(BYTE *base, PIMAGE_NT_HEADERS64 nt, DWORD *out_count)
{
    ULONG64 delta = (ULONG64)(ULONG_PTR)base - nt->OptionalHeader.ImageBase;
    IMAGE_DATA_DIRECTORY *dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    BYTE *cursor;
    DWORD left, count = 0;

    *out_count = 0;
    if (delta == 0) {
        printf("[relocs] delta=0 (base preferida); no hacen falta\n");
        return 1;
    }
    if (dir->Size == 0) {
        printf("[relocs] PE sin relocations y base distinta: imposible\n");
        return 0;
    }

    cursor = base + dir->VirtualAddress;
    left = dir->Size;
    while (left >= sizeof(IMAGE_BASE_RELOCATION)) {
        IMAGE_BASE_RELOCATION *block = (IMAGE_BASE_RELOCATION *)cursor;
        DWORD n, i;
        WORD *entry;

        if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
            block->SizeOfBlock > left) {
            break;
        }
        n = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        entry = (WORD *)(block + 1);

        for (i = 0; i < n; i++) {
            WORD type = (WORD)(entry[i] >> 12);
            WORD off = (WORD)(entry[i] & 0x0FFF);
            if (type == IMAGE_REL_BASED_DIR64) {
                ULONG64 *slot = (ULONG64 *)(base + block->VirtualAddress + off);
                *slot += delta;
                count++;
            } else if (type != IMAGE_REL_BASED_ABSOLUTE) {
                printf("[relocs] tipo no soportado: %u\n", type);
                return 0;
            }
        }
        left -= block->SizeOfBlock;
        cursor += block->SizeOfBlock;
    }

    *out_count = count;
    printf("[relocs] aplicadas: %lu (delta=0x%llX)\n",
           (unsigned long)count, (unsigned long long)delta);
    return 1;
}

static int ResolveImports(BYTE *base, PIMAGE_NT_HEADERS64 nt, DWORD *out_count)
{
    IMAGE_DATA_DIRECTORY *dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR descriptor;
    DWORD count = 0;

    *out_count = 0;
    if (dir->Size == 0) return 1;

    descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(base + dir->VirtualAddress);
    for (; descriptor->Name != 0; descriptor++) {
        const char *dll = (const char *)(base + descriptor->Name);
        HMODULE module;
        ULONG64 *names;
        ULONG64 *iat;

        if (descriptor->OriginalFirstThunk == 0) {
            printf("[imports] bound imports no soportados (%s)\n", dll);
            return 0;
        }
        module = LoadLibraryA(dll);
        if (module == NULL) {
            printf("[imports] no pude cargar %s (err=%lu)\n", dll, GetLastError());
            return 0;
        }

        names = (ULONG64 *)(base + descriptor->OriginalFirstThunk);
        iat = (ULONG64 *)(base + descriptor->FirstThunk);
        for (; *names != 0; names++, iat++) {
            FARPROC fn;
            const char *name;

            if ((*names & 0x8000000000000000ULL) != 0) {
                name = "<ordinal>";
                fn = GetProcAddress(module, (LPCSTR)(ULONG_PTR)(*names & 0xFFFF));
            } else {
                name = (const char *)(base + (*names & 0x7FFFFFFF) + 2);
                fn = (strcmp(name, "ExitProcess") == 0)
                         ? (FARPROC)ExitStub
                         : GetProcAddress(module, name);
            }
            if (fn == NULL) {
                printf("[imports] NO resuelto: %s!%s\n", dll, name);
                return 0;
            }
            *iat = (ULONG64)(ULONG_PTR)fn;
            count++;
        }
    }

    *out_count = count;
    printf("[imports] resueltos: %lu\n", (unsigned long)count);
    return 1;
}

static int RegisterExceptionTable(BYTE *base, PIMAGE_NT_HEADERS64 nt, PVOID entry,
                                  DWORD *out_entries)
{
    IMAGE_DATA_DIRECTORY *dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    HMODULE ntdll;
    PFN_RTL_ADD_FUNCTION_TABLE add;
    PFN_RTL_LOOKUP_FUNCTION_ENTRY lookup;
    HISTORY_TABLE history;
    DWORD count;
    BOOLEAN ok;
    DWORD64 image_base = 0;
    PRUNTIME_FUNCTION found;

    *out_entries = 0;
    if (dir->Size == 0) {
        printf("[pdata] el PE no tiene .pdata\n");
        return 1;
    }

    count = dir->Size / sizeof(RUNTIME_FUNCTION);
    *out_entries = count;

    ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll == NULL) {
        printf("[pdata] ntdll no encontrada\n");
        return 0;
    }
    add = (PFN_RTL_ADD_FUNCTION_TABLE)GetProcAddress(ntdll, "RtlAddFunctionTable");
    lookup = (PFN_RTL_LOOKUP_FUNCTION_ENTRY)GetProcAddress(ntdll, "RtlLookupFunctionEntry");
    if (add == NULL || lookup == NULL) {
        printf("[pdata] exports de ntdll no disponibles\n");
        return 0;
    }

    ok = add((PRUNTIME_FUNCTION)(base + dir->VirtualAddress), count,
             (DWORD64)(ULONG_PTR)base);
    printf("[pdata] RtlAddFunctionTable: %s (%lu entradas)\n",
           ok ? "ok" : "FALLO", (unsigned long)count);

    memset(&history, 0, sizeof(history));
    found = lookup((DWORD64)(ULONG_PTR)entry, &image_base, &history);
    printf("[pdata] lookup del entry: %s\n", found != NULL ? "encontrado" : "NO");

    return ok ? 1 : 0;
}

static int SetSectionProtections(BYTE *base, PIMAGE_NT_HEADERS64 nt)
{
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    WORD i;

    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        PVOID address;
        SIZE_T size;
        ULONG protection, old = 0;

        if (section[i].Misc.VirtualSize == 0) continue;
        address = base + section[i].VirtualAddress;
        size = section[i].Misc.VirtualSize;

        if ((section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) {
            protection = PAGE_EXECUTE_READ;
        } else if ((section[i].Characteristics & IMAGE_SCN_MEM_WRITE) != 0) {
            protection = PAGE_READWRITE;
        } else {
            protection = PAGE_READONLY;
        }

        if (VirtualProtect(address, size, protection, &old) == 0) {
            printf("[protect] fallo en la seccion %u (err=%lu)\n",
                   (unsigned)i, GetLastError());
            return 0;
        }
    }
    printf("[protect] secciones protegidas (RX/RW/RO)\n");
    return 1;
}

static int MapImage(const BYTE *raw, SIZE_T raw_size, MAPPED_PE *out)
{
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS64 nt;
    PIMAGE_SECTION_HEADER section;
    SIZE_T image_size;
    BYTE *base;
    DWORD entry_rva;
    WORD i;

    memset(out, 0, sizeof(*out));
    if (raw == NULL || raw_size < 0x200) {
        printf("[parse] fichero demasiado pequeno\n");
        return 0;
    }

    dos = (PIMAGE_DOS_HEADER)raw;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[parse] no es un PE: falta MZ\n");
        return 0;
    }
    if (dos->e_lfanew < 0 ||
        (SIZE_T)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > raw_size) {
        printf("[parse] e_lfanew fuera de rango\n");
        return 0;
    }

    nt = (PIMAGE_NT_HEADERS64)(raw + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        printf("[parse] firma/magic invalidos\n");
        return 0;
    }
    if (nt->FileHeader.NumberOfSections == 0 ||
        nt->FileHeader.NumberOfSections > 96) {
        printf("[parse] numero de secciones invalido\n");
        return 0;
    }

    image_size = nt->OptionalHeader.SizeOfImage;
    if (image_size == 0 || image_size > 0x4000000) {
        printf("[parse] SizeOfImage fuera de rango\n");
        return 0;
    }
    if (nt->OptionalHeader.SizeOfHeaders > raw_size ||
        nt->OptionalHeader.SizeOfHeaders > image_size) {
        printf("[parse] SizeOfHeaders invalido\n");
        return 0;
    }

    entry_rva = nt->OptionalHeader.AddressOfEntryPoint;
    if (entry_rva == 0 || entry_rva >= image_size) {
        printf("[parse] AddressOfEntryPoint invalido\n");
        return 0;
    }

    printf("[parse] MZ ok; PE64 ok; secciones=%u; ImageBase=0x%llX; "
           "SizeOfImage=0x%lX; entry RVA=0x%lX\n",
           nt->FileHeader.NumberOfSections,
           (unsigned long long)nt->OptionalHeader.ImageBase,
           (unsigned long)image_size,
           (unsigned long)entry_rva);

    base = (BYTE *)VirtualAlloc(NULL, image_size,
                                MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (base == NULL) {
        printf("[map] VirtualAlloc fallo: %lu\n", GetLastError());
        return 0;
    }
    printf("[map] base=%p (SizeOfImage=0x%lX)\n", base, (unsigned long)image_size);

    memcpy(base, raw, nt->OptionalHeader.SizeOfHeaders);
    section = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        SIZE_T virtual_size = section[i].Misc.VirtualSize;
        SIZE_T raw_segment = section[i].SizeOfRawData;

        if (virtual_size == 0) continue;
        if ((SIZE_T)section[i].VirtualAddress + virtual_size > image_size) {
            printf("[map] seccion fuera de la imagen\n");
            return 0;
        }

        memset(base + section[i].VirtualAddress, 0, virtual_size);
        if (raw_segment != 0 &&
            (SIZE_T)section[i].PointerToRawData + raw_segment <= raw_size) {
            SIZE_T copy = (raw_segment < virtual_size) ? raw_segment : virtual_size;
            memcpy(base + section[i].VirtualAddress,
                   raw + section[i].PointerToRawData, copy);
        }
    }
    printf("[map] cabeceras + secciones copiadas\n");

    if (!ApplyBaseRelocations(base, nt, &out->relocations)) return 0;
    if (!ResolveImports(base, nt, &out->imports)) return 0;
    if (!RegisterExceptionTable(base, nt, base + entry_rva, &out->pdata_entries)) {
        return 0;
    }
    if (!SetSectionProtections(base, nt)) return 0;

    out->base = base;
    out->size = image_size;
    out->entry = base + entry_rva;

    FlushInstructionCache(GetCurrentProcess(), base, image_size);
    printf("[map] listo: base=%p entry=%p\n", base, out->entry);
    return 1;
}

static DWORD WINAPI EntryThread(LPVOID parameter)
{
    PFN_ENTRY entry = (PFN_ENTRY)parameter;
    return (DWORD)entry();
}

static int ExecuteImage(MAPPED_PE *image)
{
    HANDLE thread;
    DWORD code = 0;

    thread = CreateThread(NULL, 0, EntryThread, image->entry, 0, NULL);
    if (thread == NULL) {
        printf("[run] CreateThread fallo: %lu\n", GetLastError());
        return 1;
    }
    WaitForSingleObject(thread, INFINITE);
    GetExitCodeThread(thread, &code);
    CloseHandle(thread);

    if (g_payload_exit >= 0) code = (DWORD)g_payload_exit;
    printf("[run] payload exit=%lu\n", (unsigned long)code);
    return (int)code;
}

int main(int argc, char **argv)
{
    FILE_BUFFER file;
    MAPPED_PE image;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("[pid] %lu\n", (unsigned long)GetCurrentProcessId());

    if (argc < 2) {
        printf("uso: miniload.exe <pe>\n");
        return 1;
    }
    if (!ReadWholeFile(argv[1], &file)) {
        printf("no pude leer %s\n", argv[1]);
        return 1;
    }
    if (!MapImage(file.data, file.size, &image)) {
        free(file.data);
        return 1;
    }
    free(file.data);
    return ExecuteImage(&image);
}
