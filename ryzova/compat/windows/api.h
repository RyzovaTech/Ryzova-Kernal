/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef RYZ_WINDOWS_API_H
#define RYZ_WINDOWS_API_H
#include "runtime.h"
#define CW_API_COUNT 117U
#define CW_CRT_TRACE_BLOCKS 8192U
#define CW_CRT_STREAMS 16U
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
#define CW_TRACE_HEAP_LIMIT (4U*CW_HEAP_LIMIT)
#define CW_HEAP_LIMIT_FOR(flags) ((flags)==CW_PROFILE_TRACE?CW_TRACE_HEAP_LIMIT:CW_HEAP_LIMIT)
#define CW_ENV_COUNT 16U
#define CW_COMMAND_UNITS 1024U
#define CW_CRT_ERROR_TEXT_OFFSET 6208U
#define CW_CRT_PENDING (-1)
#define CW_CRT_RETURN UINT64_C(0xffffffffff080000)
#define CW_CRT_INIT_DEPTH 8U
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
    CW_DUPLICATE_HANDLE, CW_SET_UNHANDLED_FILTER, CW_CRT_INVALID_HANDLER, CW_CRT_APP_TYPE, CW_CRT_FMODE, CW_CRT_COMMODE, CW_CRT_INITTERM, CW_CRT_INITTERM_E, CW_CRT_WENV_INIT, CW_CRT_WARGV_CONFIG, CW_CRT_ARGC, CW_CRT_WARGV, CW_CRT_WENV, CW_CRT_NEW_MODE, CW_CRT_ATEXIT, CW_CRT_CEXIT, CW_CRT_EXIT, CW_CRT_QUICK_EXIT, CW_MODULE_HANDLE_A, CW_PROC_ADDRESS, CW_CRT_RAND_S, CW_WIDE_TO_MULTI, CW_CRT_SETLOCALE,
    CW_CRT_IOB, CW_CRT_FILENO, CW_CRT_SETMODE, CW_CRT_ISATTY, CW_CRT_OSFHANDLE, CW_CRT_WFOPEN, CW_CRT_GETC, CW_CRT_FREAD, CW_CRT_FGETS, CW_CRT_FEOF, CW_CRT_FERROR, CW_CRT_CLEARERR, CW_CRT_FCLOSE, CW_CRT_FFLUSH, CW_CRT_FPUTC, CW_CRT_FPUTS, CW_CRT_FWRITE, CW_CRT_PUTCHAR, CW_CRT_PUTS, CW_CRT_WRITE, CW_GET_CONSOLE_MODE,
    CW_CRT_ISALPHA, CW_CRT_ISALNUM, CW_CRT_ISSPACE, CW_CRT_STRCHR, CW_CRT_STRRCHR, CW_CRT_MEMCHR, CW_CRT_STRNLEN, CW_CRT_WCSNLEN, CW_CRT_STRDUP, CW_CRT_STRCPY, CW_CRT_STRNCPY, CW_CRT_GETENV, CW_CRT_LOCALE_CODEPAGE, CW_MULTI_TO_WIDE, CW_DBCS_LEAD_BYTE, CW_CRT_FULLPATH, CW_PATH_IS_RELATIVE, CW_GET_THREAD_PRIORITY, CW_SET_THREAD_PRIORITY, CW_CRT_STRERROR, CW_CRT_LOCK_FILE, CW_CRT_UNLOCK_FILE };
typedef struct CwEnvironment { uint16_t name[64], value[256]; } CwEnvironment;
typedef struct CwLaunch {
    uint32_t api_mask, console_mask, environment_count;
    uint16_t command_line[CW_COMMAND_UNITS];
    CwEnvironment environment[CW_ENV_COUNT];
    uint32_t api_mask_high[CW_API_WORDS-1];
    uint32_t profile_flags;
} CwLaunch;
typedef struct CwAllocation { uint32_t first, pages; } CwAllocation;
typedef struct CwCrtBlock { uint64_t base,size,capacity; } CwCrtBlock;
typedef struct CwSyncObject { uint32_t type,flags,count,maximum,refs; } CwSyncObject;
typedef struct CwSyncHandle { uint64_t token;uint32_t object,access,flags; } CwSyncHandle;
typedef struct CwCritical { uint64_t address;uint32_t depth; } CwCritical;
typedef int (*CwRandomRead)(void *,unsigned char *,size_t);
typedef struct CwCrtInit { uint64_t cursor,end,stack,ret;uint32_t checked,code; } CwCrtInit;
typedef struct CwCrtStream {
    uint64_t token,handle;
    uint32_t mode,start,end,eof,error;
    unsigned char buffer[512];
} CwCrtStream;
struct CwServices {
    CwLaunch launch;
    uint32_t last_error, output_bytes[2], calls[CW_API_COUNT];
    unsigned char output[2][CW_OUTPUT_LIMIT], command_bytes[CW_COMMAND_UNITS*2];
    uint64_t command_base, heap_base;
    unsigned char *heap;
    size_t heap_bytes;
    unsigned char owner[CW_TRACE_HEAP_LIMIT/4096], protection[CW_TRACE_HEAP_LIMIT/4096];
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
    uint64_t exception_filter;
    uint64_t invalid_parameter_handler;
    uint32_t crt_app_type;
    unsigned char crt_globals[32];
    unsigned char crt_argv[4096],crt_environment[12288];
    uint32_t crt_argv_ready,crt_environment_ready;
    CwCrtInit crt_initializers[CW_CRT_INIT_DEPTH];
    uint32_t crt_init_depth;
    uint32_t crt_new_mode;
    uint64_t crt_exit_callbacks[32];
    uint32_t crt_exit_count;
    uint32_t dynamic_apis[CW_API_WORDS];
    CwRandomRead random_read;
    void *random_context;
    uint32_t crt_stream_serial;
    CwCrtStream crt_streams[CW_CRT_STREAMS];
    uint64_t trace_crt_base,trace_crt_size;
    unsigned int trace_crt_count;
    CwCrtBlock trace_crt_blocks[CW_CRT_TRACE_BLOCKS];
    unsigned char crt_narrow_env[CW_ENV_COUNT][256];
    int32_t thread_priority;
    unsigned char crt_error_text[32];
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
int cw_crt_continue(CwMachine *);
int cw_crt_trace_span(const CwServices *,uint64_t,size_t);
int cw_crt_owned(CwMachine *,uint64_t);
int cw_crt_export(unsigned int);
const char *cw_crt_alias(unsigned int);
int cw_sync_call(CwMachine *,unsigned int,const uint64_t *,uint64_t *);
int cw_sync_handle_family(uint64_t);
/* CPU dispatches only exact declared thunk tokens; every call consumes a step. */
int cw_api_dispatch(CwMachine *);
unsigned char *cw_service_memory(CwMachine *,uint64_t,size_t,unsigned int);
#endif
