/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef RYZ_WINDOWS_API_H
#define RYZ_WINDOWS_API_H
#include "runtime.h"
#define CW_API_COUNT 9U
#define CW_ALL_APIS ((1U<<CW_API_COUNT)-1U)
#define CW_OUTPUT_LIMIT 65536U
#define CW_HEAP_LIMIT (1024U*1024U)
#define CW_ENV_COUNT 16U
#define CW_COMMAND_UNITS 1024U
#define CW_THUNK_BASE UINT64_C(0xffffffffff000000)
enum CwApi { CW_GET_STD_HANDLE, CW_WRITE_FILE, CW_EXIT_PROCESS, CW_GET_LAST_ERROR,
    CW_SET_LAST_ERROR, CW_GET_COMMAND_LINE, CW_GET_ENVIRONMENT_VARIABLE,
    CW_VIRTUAL_ALLOC, CW_VIRTUAL_FREE };
typedef struct CwEnvironment { uint16_t name[64], value[256]; } CwEnvironment;
typedef struct CwLaunch {
    uint32_t api_mask, console_mask, environment_count;
    uint16_t command_line[CW_COMMAND_UNITS];
    CwEnvironment environment[CW_ENV_COUNT];
} CwLaunch;
typedef struct CwAllocation { uint32_t first, pages; } CwAllocation;
typedef struct CwServices {
    CwLaunch launch;
    uint32_t last_error, output_bytes[2], calls[CW_API_COUNT];
    unsigned char output[2][CW_OUTPUT_LIMIT], command_bytes[CW_COMMAND_UNITS*2];
    uint64_t command_base, heap_base;
    unsigned char *heap;
    size_t heap_bytes;
    unsigned char owner[CW_HEAP_LIMIT/4096], protection[CW_HEAP_LIMIT/4096];
    CwAllocation allocations[16];
    CwMachine *owner;
} CwServices;
/* Zero-initialize services before first attach; a service belongs to one machine.
   Trusted launcher attaches explicit policy/backing, never host env/DLLs. */
int cw_attach_services(CwMachine *,CwServices *,const CwLaunch *,unsigned char *,size_t);
int cw_api_id(const char *);
const char *cw_api_name(unsigned int);
uint64_t cw_api_token(unsigned int);
/* CPU dispatches only exact declared thunk tokens; every call consumes a step. */
int cw_api_dispatch(CwMachine *);
unsigned char *cw_service_memory(CwMachine *,uint64_t,size_t,unsigned int);
#endif
