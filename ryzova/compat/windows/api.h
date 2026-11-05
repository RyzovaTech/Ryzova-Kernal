/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef RYZ_WINDOWS_API_H
#define RYZ_WINDOWS_API_H
#include "runtime.h"
#define CW_API_COUNT 52U
#define CW_SYNC_OBJECTS 32U
#define CW_SYNC_HANDLES 64U
#define CW_CRITICAL_LIMIT 32U
#define CW_LEGACY_APIS ((1U<<28)-1U)
/* Preserve the old source-level grant; new IDs require explicit words. */
#define CW_ALL_APIS CW_LEGACY_APIS
#define CW_LOW_API_MASK UINT32_MAX
#define CW_DYNAMIC_TLS_SLOTS 64U
#define CW_OUTPUT_LIMIT 65536U
#define CW_HEAP_LIMIT (1024U*1024U)
#define CW_ENV_COUNT 16U
#define CW_COMMAND_UNITS 1024U
#define CW_THUNK_BASE UINT64_C(0xffffffffff000000)
enum CwApi { CW_GET_STD_HANDLE, CW_WRITE_FILE, CW_EXIT_PROCESS, CW_GET_LAST_ERROR,
    CW_SET_LAST_ERROR, CW_GET_COMMAND_LINE, CW_GET_ENVIRONMENT_VARIABLE,
    CW_VIRTUAL_ALLOC, CW_VIRTUAL_FREE, CW_CREATE_FILE, CW_READ_FILE, CW_CLOSE_HANDLE,
    CW_SET_FILE_POINTER, CW_GET_FILE_SIZE, CW_FLUSH_FILE_BUFFERS,
    CW_MEMCPY, CW_MEMMOVE, CW_MEMSET, CW_MEMCMP, CW_STRLEN, CW_STRCMP, CW_STRNCMP, CW_WCSLEN,
    CW_MALLOC, CW_CALLOC, CW_REALLOC, CW_FREE, CW_ERRNO,
    CW_FILE_APIS_ANSI, CW_FILE_APIS_SET_ANSI, CW_FILE_APIS_SET_OEM,
    CW_TLS_ALLOC, CW_TLS_FREE, CW_TLS_GET, CW_TLS_SET,
    CW_CREATE_EVENT, CW_SET_EVENT, CW_RESET_EVENT, CW_CREATE_SEMAPHORE, CW_RELEASE_SEMAPHORE,
    CW_WAIT_SINGLE, CW_WAIT_MULTIPLE, CW_CRITICAL_INIT, CW_CRITICAL_DELETE,
    CW_CRITICAL_ENTER, CW_CRITICAL_LEAVE, CW_CRITICAL_TRY,
    CW_CURRENT_PROCESS, CW_CURRENT_PROCESS_ID, CW_CURRENT_THREAD, CW_CURRENT_THREAD_ID,
    CW_DUPLICATE_HANDLE };
typedef struct CwEnvironment { uint16_t name[64], value[256]; } CwEnvironment;
typedef struct CwLaunch {
    uint32_t api_mask, console_mask, environment_count;
    uint16_t command_line[CW_COMMAND_UNITS];
    CwEnvironment environment[CW_ENV_COUNT];
    uint32_t api_mask_high[CW_API_WORDS-1];
} CwLaunch;
typedef struct CwAllocation { uint32_t first, pages; } CwAllocation;
typedef struct CwCrtBlock { uint64_t base,size,capacity; } CwCrtBlock;
typedef struct CwSyncObject { uint32_t type,flags,count,maximum,refs; } CwSyncObject;
typedef struct CwSyncHandle { uint64_t token;uint32_t object,access,flags; } CwSyncHandle;
typedef struct CwCritical { uint64_t address;uint32_t depth; } CwCritical;
struct CwServices {
    CwLaunch launch;
    uint32_t last_error, output_bytes[2], calls[CW_API_COUNT];
    unsigned char output[2][CW_OUTPUT_LIMIT], command_bytes[CW_COMMAND_UNITS*2];
    uint64_t command_base, heap_base;
    unsigned char *heap;
    size_t heap_bytes;
    unsigned char owner[CW_HEAP_LIMIT/4096], protection[CW_HEAP_LIMIT/4096];
    CwAllocation allocations[16];
    CwMachine *bound_machine;
    struct CwFileNamespace *files;
    uint32_t console_closed;
    CwCrtBlock crt_blocks[16];
    unsigned char errno_bytes[4];
    uint32_t file_apis_ansi, tls_used[2];
    uint64_t tls_values[CW_DYNAMIC_TLS_SLOTS];
    uint32_t sync_serial;
    CwSyncObject sync_objects[CW_SYNC_OBJECTS];
    CwSyncHandle sync_handles[CW_SYNC_HANDLES];
    CwCritical criticals[CW_CRITICAL_LIMIT];
};
/* Zero-initialize services before first attach; a service belongs to one machine.
   Trusted launcher attaches explicit policy/backing, never host env/DLLs. */
int cw_attach_services(CwMachine *,CwServices *,const CwLaunch *,unsigned char *,size_t);
int cw_api_id(const char *);
const char *cw_api_name(unsigned int);
uint64_t cw_api_token(unsigned int);
const char *cw_api_module(unsigned int);
/* Exact supported import contracts; never load or forward to a host DLL. */
int cw_api_module_id(const char *);
int cw_api_module_matches(unsigned int,const char *);
uint32_t cw_api_word_mask(unsigned int);
int cw_plan_has_api(const CwPlan *,unsigned int);
void cw_plan_add_api(CwPlan *,unsigned int);
int cw_launch_allows_plan(const CwLaunch *,const CwPlan *);
uint64_t cw_heap_allocate(CwMachine *,uint64_t);
int cw_heap_release(CwMachine *,uint64_t);
int cw_crt_call(CwMachine *,unsigned int,const uint64_t *,uint64_t *);
int cw_crt_owned(CwMachine *,uint64_t);
int cw_sync_call(CwMachine *,unsigned int,const uint64_t *,uint64_t *);
int cw_sync_handle_family(uint64_t);
/* CPU dispatches only exact declared thunk tokens; every call consumes a step. */
int cw_api_dispatch(CwMachine *);
unsigned char *cw_service_memory(CwMachine *,uint64_t,size_t,unsigned int);
#endif
