/*

This is not produciton code. Errors are not handled gracefully.
This is a vacation project, so I'm mostly just doing the fun stuff.

Architecture looks something like:
 Main Thread:
  - init memory_tracker
  - start memory_tracker_thread
  - start etw_thread
  - wait
 Memory Tracker Thread:
  - loop:
    - check address_queue
      - process until empty
      - check event_queue
        - process until empty
        - process warm & stale addrs
 ETW Thread:
  - receive event
  - classify event
  - push onto correct queue
  - repeat

Its fine probably.. Its nice to process the memory & process events
inside the memory tracker thread cause then you don't have to
worry about locking the memory tracker data when you're updating it.
Its the little things yaknow.

Had a little fun with the data structures but they're incomplete
and could be a little more user friendly / ergonomic.
And I kind of forced the "growable_array"/arena to work for this scenario.
*/

// TODO: Intel PT, but my laptop is ancient and doesn't support it..
// TODO: TI events, but I don't really want to testsign stuff atm.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdlib.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <evntrace.h>
#include <evntcons.h>
#include <psapi.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "onecore.lib")
#pragma comment(lib, "winmm.lib")

#define KB(x) (x*1024)
#define MB(x) (x*1024*1024)

// Technically not correct but fine anyway
#define PAGE_SIZE KB(4)
#define PAGE_ROUND_UP(x) (((x)+PAGE_SIZE-1) & ~(PAGE_SIZE-1))

// this is fine
#include "./growable_array.c"
#include "./swsr_ringbuffer.c"

NTSTATUS
NTAPI
NtQueryVirtualMemory(
  _In_ HANDLE ProcessHandle,
  _In_opt_ PVOID BaseAddress,
  _In_ DWORD MemoryInformationClass,
  _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
  _In_ SIZE_T MemoryInformationLength,
  _Out_opt_ PSIZE_T ReturnLength
);
NTSTATUS
NTAPI
NtSetSystemInformation(
  _In_ DWORD SystemInformationClass,
  _In_reads_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
  _In_ ULONG SystemInformationLength
);



// Thanks TraceEvent:
typedef enum 
{
  None = 0,
  FilterKernel = 1 << 0,
  FilterUser = 1 << 1,
  FilterJcc = 1 << 2,
  FilterNearRelCall = 1 << 3,
  FilterNearIndCall = 1 << 4,
  FilterNearRet = 1 << 5,
  FilterNearIndJmp = 1 << 6,
  FilterNearRelJmp = 1 << 7,
  FilterFarBranch = 1 << 8,
  CallstackEnable = 1 << 9,
}LbrFilterFlags;

#define MemoryBasicInformation 0x0

// Thanks MSDN:
BOOL set_privilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
  TOKEN_PRIVILEGES tp;
  LUID luid;

  if (!LookupPrivilegeValueA(NULL, lpszPrivilege, &luid )) {
    printf("LookupPrivilegeValue error: %u\n", GetLastError()); 
    return FALSE; 
  }

  tp.PrivilegeCount = 1;
  tp.Privileges[0].Luid = luid;
  if (bEnablePrivilege)
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  else
    tp.Privileges[0].Attributes = 0;

  if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES) NULL, (PDWORD) NULL)) {
    printf("AdjustTokenPrivileges error: %u\n", GetLastError()); 
    return FALSE; 
  } 

  if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
    printf("The token does not have the specified privilege. \n");
    return FALSE;
  } 

  return TRUE;
}

// From some gist somewhere but its not great..
void DumpHex(LPVOID data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

#define EventTraceProcessorTraceConfigurationInformation 0x17
#define EventTraceProcessorTraceEventListInformation 0x18
#define SystemPerformanceTraceInformation 0x1F

typedef struct tag_event_trace_ipt_config_info {
  DWORD EventTraceInformationClass;
  TRACEHANDLE TraceHandle;
  struct {
    DWORD TraceMode        : 4;
    DWORD TimeMode         : 4;
    DWORD MTCFreq          : 4;
    DWORD CycThresh        : 4;
    DWORD BufferSize       : 4;
    DWORD TraceSessionMode : 3;
    DWORD TraceChild       : 1;
    DWORD TraceCodeMode    : 4;
    DWORD Reserved2        : 4;
    DWORD Reserved3;
  } IptOptions;
} Event_Trace_IPT_Config_Info;

typedef struct tag_event_trace_ipt_hook_info {
  DWORD EventTraceInformationClass;
  TRACEHANDLE TraceHandle;
  DWORD HookIds[ANYSIZE_ARRAY];
} Event_Trace_Ipt_List_Info;

// Thanks winipt (ionescu) for all ipt definitions 
typedef enum _IPT_MATCH_SETTINGS
{
  IptMatchByAnyApp,
  IptMatchByImageFileName,
  IptMatchByAnyPackage,
  IptMatchByPackageName,
} IPT_MATCH_SETTINGS, *PIPT_MATCH_SETTINGS;

typedef enum _IPT_MODE_SETTINGS
{
  //
  // Set through IOCTL (IptStartCoreIptTracing)
  //
  IptCtlUserModeOnly,                 // Sets BranchEn[2000], ToPA[100], User[8]
  IptCtlKernelModeOnly,               // Sets BranchEn[2000], ToPA[100], OS[4]
  IptCtlUserAndKernelMode,            // Sets BranchEn[2000], ToPA[100], User[8], OS[4]

  //
  // Set through registry (IptOptions)
  //
  IptRegUserModeOnly,                 // Sets BranchEn[2000], ToPA[100], User[8]
  IptRegKernelModeOnly,               // Sets BranchEn[2000], ToPA[100], OS[4]
  IptRegUserAndKernelMode,            // Sets BranchEn[2000], ToPA[100], User[8], OS[4]
} IPT_MODE_SETTINGS, *PIPT_MODE_SETTINGS;

typedef enum IPT_TIMING_SETTINGS
{
  IptNoTimingPackets,                 // No additional IA32_RTIT_CTL bits enabled
  IptEnableMtcPackets,                // Sets MTCEn[200], TSCEn[400]. Requires CPUID.(EAX=014H,ECX=0H):EBX[3]= 1
  IptEnableCycPackets                 // Sets MTCEn[200], TSCEn[400], CYCEn[2]. Requires CPUID.(EAX=014H,ECX=0H):EBX[1]= 1
} IPT_TIMING_SETTINGS, *PIPT_TIMING_SETTINGS;

static const GUID Fu_ThreadGuid = { 0x3d6fa8d1, 0xfe05, 0x11d0, { 0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c } };
static const GUID Fu_PerfInfoGuid = { 0xce1dbfb4, 0x137e, 0x4da6, { 0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc } };
static const GUID Fu_LbrGuid = {0x99134383, 0x5248, 0x43FC, {0x83, 0x4B, 0x52, 0x94, 0x54, 0xE7, 0x5D, 0xF3}};
static const GUID Fu_StackWalkGuid = {0xdef2fe46, 0x7bd6, 0x4b80, {0xbd, 0x94, 0xf5, 0x7f, 0xe2, 0x0d, 0x0c, 0xe3}};
static const GUID Fu_ProcessGuid = { 0x3d6fa8d0, 0xfe05, 0x11d0, { 0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}};
static const GUID Fu_PageFaultGuid = { 0x3d6fa8d3, 0xfe05, 0x11d0, { 0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}};

typedef enum {
  ADDR_NotFound,
  ADDR_ImageBacked,
  ADDR_NotImageBacked
} AddressKind;

// I should probably benchmark if the pack is even helpful here..
#pragma pack(push, 4)
typedef struct tag_memory_region {
  DWORD64 low;
  DWORD64 high;
  DWORD unbacked_hit; // easiest way to track this, idealy I'd like this to be tracked elsewhere for memory locality reasons
} Memory_Region;
#pragma pack(pop)

// this should be whatever the PAGE size is.. so it should be
// a runtime thing, but I'm just gunna hardcode it to 4kb
#define MAX_MEM_REGIONS ((PAGE_SIZE - (sizeof(DWORD)*4)) / sizeof(Memory_Region))

// This should be exactly one page now
#pragma pack(push, 4)
typedef struct tag_process_memory {
  struct tag_process_memory *next;
  Memory_Region regions[MAX_MEM_REGIONS];
  DWORD num_regions;
  DWORD padding;
} Process_Memory;
#pragma pack(pop)

typedef struct tag_proc_name {
  LPVOID next;
  char name[MAX_PATH];
} Process_Name;

typedef struct tag_process {
  LPVOID next;
  DWORD pid;
  Process_Memory *memory;
  Process_Name *name;
} Process;

// TODO: better memory management that is not reliant on malloc/frees everywhere
//       until then.. just used fixed sized blocks
#define MAX_PROCESSES (0x1000 / sizeof(Process))

typedef struct tag_addrs_to_check {
  DWORD pid;
  DWORD num;
  DWORD64 addresses[0];
} Addresses_To_Check;

typedef struct tag_addr_to_check{
  DWORD pid;
  DWORD64 address;
} Address_To_Check;

#define ADDR_QUEUE_SZ MB(12)
#define MAX_WARM_ADDRS (1024 * 4)
#define MAX_STALE_ADDRS (1024 * 4)
typedef struct tag_memory_tracker {
  DWORD num_processes;
  Growable_Array processes;
  Growable_Array processes_memory;
  Growable_Array process_names;
  DWORD *tracked_unbacked_addrs;

  SWSR_Ring_Buffer check_addr_queue;
  SWSR_Ring_Buffer event_queue;
  DWORD64 addrs_added;
  DWORD64 addrs_checked;
  DWORD64 addrs_dropped;
  DWORD warm_addrs_idx;
  Address_To_Check warm_addrs[MAX_WARM_ADDRS];
  DWORD stale_addrs_idx;
  Address_To_Check stale_addrs[MAX_STALE_ADDRS];
} Memory_Tracker;

typedef struct tag_stack_walk_event {
  DWORD64 EventTimeStamp;
  DWORD StackProcess;
  DWORD StackThread;
  DWORD64 Stack[0];
} ETW_Event_Stack_Walk;

typedef enum {
  Fu_DontCare = 0,
  Fu_StackWalkEvent,
  Fu_LbrStackWalkEvent,
  Fu_ProcessStartEvent,
  Fu_ProcessEndEvent,
  Fu_VirtualAllocEvent,
} EventKind;

typedef struct tag_event_header {
  EventKind kind;
  DWORD pid;
} Event_Header;

typedef struct tag_event_virtual_alloc {
  Event_Header header;
  DWORD64 address;
  DWORD64 size;
} Event_Virtual_Alloc;

typedef struct tag_process_etw_event {
  DWORD64 UniqueProcessKey;
  DWORD ProcessId;
  DWORD ParentId;
  // etc ...  
} ETW_Event_Process;

#pragma pack(push, 4)
typedef struct tag_virtual_alloc_etw_event {
  DWORD64 BaseAddress;
  DWORD RegionSize;
  DWORD ProcessId;
  DWORD Flags;
} EWT_Event_Virtual_Alloc;
#pragma pack(pop)

// Well, this was going to do something completely different
// But this seems easiest, maybe not
void track_unbacked_addr(Process *proc, Memory_Region *region) {
  region->unbacked_hit += 1;
}

void print_process_stats(Process *proc) {
  BOOL displayed_name = FALSE;
  Process_Memory *pm = proc->memory;
  while (pm) {
    for (DWORD r = 0; r < pm->num_regions; r++) {
      if (pm->regions[r].unbacked_hit > 0) {
        if (!displayed_name) {
          displayed_name = TRUE;
          printf("%s (%u)\n", proc->name->name, proc->pid);
        }
        printf(" [%u] { 0x%p - 0x%p }\n", pm->regions[r].unbacked_hit ,pm->regions[r].low, pm->regions[r].high);
      }
    }
    pm = pm->next;
  }
}

// I'm certian you can make this faster, at a minimum with SIMD
AddressKind check_address_kind(DWORD64 addr, const Process_Memory *pm, Memory_Region **found_region) {
  const Process_Memory *cur_pm = pm;
  while (cur_pm) {    
    const Memory_Region *region = cur_pm->regions;
    const DWORD num_regions = cur_pm->num_regions;
    for (DWORD i = 0; i < num_regions; i++, region++) {
      if (addr >= region->low && addr < region->high) {
        *found_region = region;
        return ADDR_NotImageBacked;
      }
    }
    cur_pm = cur_pm->next;
  }
  return ADDR_NotFound;
}

BOOL query_single_mem_region(HANDLE process, Process_Memory *pm, DWORD64 *pbase) {
  if (pm->num_regions >= MAX_MEM_REGIONS) return FALSE;
  DWORD64 base = *pbase;

  MEMORY_BASIC_INFORMATION mbi = {0};
  DWORD64 retLen = 0;

  NTSTATUS ns = NtQueryVirtualMemory(process, (PVOID)base, MemoryBasicInformation, &mbi, sizeof(mbi), &retLen);
  if (!NT_SUCCESS(ns)) {
    if (ns != STATUS_INVALID_PARAMETER)
      printf("Failed to QueryVirtualMemory for proc. 0x%08x\n", ns);
    return FALSE;
  }
  if (mbi.Type & MEM_IMAGE || !(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
    *pbase = (DWORD64)mbi.BaseAddress + (DWORD64)mbi.RegionSize;
    return TRUE;
  }
  DWORD idx = pm->num_regions;
  pm->num_regions += 1;
  pm->regions[idx].low = base;
  *pbase = (DWORD64)mbi.BaseAddress + (DWORD64)mbi.RegionSize;
  pm->regions[idx].high = *pbase;
  //pm->regions[idx].info = mbi.Type;
  return TRUE;
}

BOOL query_all_mem_regions_for_process(Memory_Tracker *mt, HANDLE process, Process_Memory *pm) {
  DWORD64 base = 0;
  NTSTATUS ns = 0;
  BOOL success = FALSE;
  Process_Memory *cur_pm = pm;
  do {
    success = query_single_mem_region(process, cur_pm, &base);
    if (cur_pm->num_regions == MAX_MEM_REGIONS) {
      cur_pm->next = new_item_growable_array(&mt->processes_memory);
      cur_pm = cur_pm->next;
    }
  } while(success);
  return (cur_pm == pm && cur_pm->num_regions > 0) || (cur_pm != pm);
}

BOOL memory_tracker_initialize_processes(Memory_Tracker *mt) {
  HANDLE hProcessSnap;
  HANDLE hProcess;
  PROCESSENTRY32 pe32;

  hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hProcessSnap == INVALID_HANDLE_VALUE) {
    printf("Failed to snapshot processes. 0x%08\n", GetLastError());
    return FALSE;
  }

  pe32.dwSize = sizeof(PROCESSENTRY32);

  if (!Process32First(hProcessSnap, &pe32)) {
    printf("Failed to get first proc in snapshot. 0x%08\n", GetLastError());
    CloseHandle(hProcessSnap);
    return FALSE;
  }

  do {
    if (pe32.th32ProcessID == 4 || pe32.th32ProcessID == 0) continue;
    Process *proc = new_item_growable_array(&mt->processes);
    if (!proc) return FALSE;

    mt->num_processes += 1;
    proc->name = new_item_growable_array(&mt->process_names);
    proc->memory = new_item_growable_array(&mt->processes_memory);
    proc->pid = pe32.th32ProcessID;
    //          ->name->name feels silly
    strncpy(proc->name->name, pe32.szExeFile, sizeof(proc->name->name));

    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
    if (hProcess == NULL) {
      printf("Failed to OpenProcess(%u): %s. 0x%08\n", pe32.th32ProcessID, pe32.szExeFile, GetLastError());
    }
    else {
      // printf("Getting Mem for %s(%u)\n", pe32.szExeFile, pe32.th32ProcessID);
      BOOL success = query_all_mem_regions_for_process(mt, hProcess, proc->memory);
      CloseHandle(hProcess);
      if (!success) {
        // printf("Failed to initialize memory tracker for process: %s(%u)\n -> This probably means no unbacked exec memory.\n", pe32.szExeFile, pe32.th32ProcessID);
      }
    }
  } while (Process32Next(hProcessSnap, &pe32));

  CloseHandle(hProcessSnap);
  return TRUE;
}

void process_ended(Memory_Tracker *mt, DWORD pid) {
  Process *processes = (Process*)mt->processes.address;
  for (DWORD i = 0; i < mt->num_processes; i++) {
    if (processes[i].pid == pid) {
      print_process_stats(&processes[i]);
      processes[i].memory->num_regions = 0;
      Process_Memory *pm = processes[i].memory;
      while (pm) {
        Process_Memory *prev = pm;
        pm = prev->next;
        release_item_growable_array(&mt->processes_memory, prev);
      }
      release_item_growable_array(&mt->process_names, processes[i].name);
      release_item_growable_array(&mt->processes, &processes[i]);
      break;
    }
  }
}

// can definitely do /alot/ to make this faster
void process_warm_and_stale_addrs(Memory_Tracker *mt) {
  Memory_Region *found_region = NULL;
  Process *processes = (Process*)mt->processes.address;

  // warm addrs
  for (DWORD i = 0; i < mt->warm_addrs_idx; i++) {
    Address_To_Check atc = mt->warm_addrs[i];
    if (atc.pid == 0) continue;
    for (DWORD proc_idx = 0; proc_idx < mt->num_processes; proc_idx++) {
      if (processes[proc_idx].pid == atc.pid) {
        AddressKind kind = check_address_kind(atc.address, processes[proc_idx].memory, &found_region);
        if (kind == ADDR_NotImageBacked) {
          track_unbacked_addr(&processes[proc_idx], found_region);
          mt->warm_addrs[i] = (Address_To_Check){0};
        }
        break;
      }
    }
  }

  // stale addrs
  for (DWORD i = 0; i < mt->stale_addrs_idx; i++) {
    Address_To_Check atc = mt->stale_addrs[i];
    if (atc.pid == 0) continue;
    for (DWORD proc_idx = 0; proc_idx < mt->num_processes; proc_idx++) {
      if (processes[proc_idx].pid == atc.pid) {
        AddressKind kind = check_address_kind(atc.address, processes[proc_idx].memory, &found_region);
        if (kind == ADDR_NotImageBacked) {
          track_unbacked_addr(&processes[proc_idx], found_region);
          mt->stale_addrs[i] = (Address_To_Check){0};
        }
        break;
      }
    }
  }
}


// needs a bit of a rework, there is a lot of duplicated code slightly modified here
DWORD process_event_queue(Memory_Tracker *mt) {
  DWORD processed_events = 0;
  Process *processes = (Process*)mt->processes.address;
  while (TRUE) {
    Event_Header *header = NULL;
    header = (Event_Header*) swsr_try_read(&mt->event_queue, sizeof(Event_Header));
    if (!header) return processed_events;
    if (header->kind == Fu_VirtualAllocEvent) {
      PBYTE can_read = swsr_try_read(&mt->event_queue, sizeof(Event_Virtual_Alloc) - sizeof(Event_Header));
      if (!can_read) {
        swsr_revert_read(&mt->event_queue);
        return processed_events;
      }
      Event_Virtual_Alloc *event = (Event_Virtual_Alloc*)header;
      HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, header->pid);
      if (hProcess && hProcess != INVALID_HANDLE_VALUE) {
        Process_Memory *pm = NULL;
        for (DWORD i = 0; i < mt->num_processes; i++) {
          if (processes[i].pid == header->pid) {
            pm = processes[i].memory;
            break;
          }
        }
        if (pm) {
          DWORD64 base = event->address;
          DWORD64 high = event->address+event->size;
          BOOL success = TRUE;
          while (success && base < high) {
            success = query_single_mem_region(hProcess, pm, &base);
            if (pm->num_regions == MAX_MEM_REGIONS) {
              pm->next = new_item_growable_array(&mt->processes_memory);
              pm = pm->next;
            }
          }
          if (success && base != high) {
            printf("Region, after queired was not same size as event said. %p-%p vs expected %p-%p\n", event->address, base, event->address, high);
          }
        }
        CloseHandle(hProcess);
      }
    }
    else if (header->kind == Fu_ProcessStartEvent) {
      // Probably worth it to tombstone these for some time
      process_ended(mt, header->pid);

      HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, header->pid);
      if (hProcess && hProcess != INVALID_HANDLE_VALUE) {
        Process *proc = new_item_growable_array(&mt->processes);
        if (proc) {
          proc->pid = header->pid;
          proc->name = new_item_growable_array(&mt->process_names);
          proc->memory = new_item_growable_array(&mt->processes_memory);
          mt->num_processes = mt->processes.used / mt->processes.type_sz;
          // not exactly the same as the initial listing.. but its fine..
          GetProcessImageFileNameA(hProcess, proc->name->name, sizeof(proc->name->name));
          query_all_mem_regions_for_process(mt, hProcess, proc->memory);
        }
        CloseHandle(hProcess);
      }
    }
    else if (header->kind == Fu_ProcessEndEvent) {
      process_ended(mt, header->pid);
    }
    else {
      // unknown event
    }
    swsr_commit_read(&mt->event_queue);
    processed_events += 1;
  }
}

// The burstiness of the events requires a large(ish) address queue,
// otherwise events start to drop =[
// The main "cost" in this proc is WaitOnAddress, because yaknow, its waiting.
// So there should be time for the other events to be processed.
DWORD CALLBACK memory_tracker_thread(LPVOID Arg) {
  Memory_Tracker *mt = (Memory_Tracker*)Arg;
  while (TRUE) {
    Addresses_To_Check *checkme = NULL;
    checkme = (Addresses_To_Check*) swsr_try_read(&mt->check_addr_queue, sizeof(Addresses_To_Check));
    if (!checkme) {
      // If we're done processing for now, we use this time to address new proc & memory change events.
      DWORD num_processed = process_event_queue(mt);
      if (num_processed > 0) {
        process_warm_and_stale_addrs(mt);
      }
      // TODO: we could also do event correlation here
      DWORD zero = 0;
      WaitOnAddress(&mt->check_addr_queue.count, &zero, 4, INFINITE);
      continue;
    }
    // this shouldn't ever happen
    if (checkme->num == 0) {
      swsr_commit_read(&mt->check_addr_queue);
      continue;
    }
    PBYTE rem_addrs = swsr_try_read(&mt->check_addr_queue, checkme->num * sizeof(DWORD64));
    if (!rem_addrs) {
      swsr_revert_read(&mt->check_addr_queue);
      continue;
    }

    DWORD pid = checkme->pid;
    // printf("- PID(%u) 0x%p #%u Count: %u - %u\n", checkme->pid, checkme, checkme->num, 999, 8+checkme->num*8);
    Process_Memory *pm = NULL;
    Process *processes = (Process*)mt->processes.address;
    DWORD proc_idx = 0;
    for (proc_idx = 0; proc_idx < mt->num_processes; proc_idx++) {
      if (processes[proc_idx].pid == pid) {
        pm = processes[proc_idx].memory;
        break;
      }
    }
    if (pm == NULL) {
      //printf("Failed to find a processes for the Address Check event with PID: %u\n", checkme->pid);
    }
    else {
      // pulling these out seem to /sometimes/ generate better assembly
      DWORD stale_idx = mt->stale_addrs_idx;
      DWORD warm_idx = mt->warm_addrs_idx;
      for (DWORD i = 0; i < checkme->num; i++) {
        DWORD64 addr = checkme->addresses[i];
        Memory_Region *found_region = 0;
        AddressKind kind = check_address_kind(addr, pm, &found_region);

        // TODO: This is kind of slow
        if (kind == ADDR_NotFound) {
          if (mt->warm_addrs[warm_idx].pid) {
            mt->stale_addrs[stale_idx++] = mt->warm_addrs[warm_idx];
            if (stale_idx >= MAX_WARM_ADDRS) stale_idx -= MAX_STALE_ADDRS;
          }
          mt->warm_addrs[warm_idx++] = (Address_To_Check){pid, addr};
          if (warm_idx >= MAX_WARM_ADDRS) warm_idx -= MAX_WARM_ADDRS;
        }
        else if (kind == ADDR_NotImageBacked) {
          track_unbacked_addr(&processes[proc_idx], found_region);
        }
      }
      mt->stale_addrs_idx = stale_idx;
      mt->warm_addrs_idx = warm_idx;
    }
    mt->addrs_checked += checkme->num;
    swsr_commit_read(&mt->check_addr_queue);
  }
}


Memory_Tracker memory_tracker = {0};
BOOL memory_tracker_init() {
  printf("size of mem manager: %u bytes\n", sizeof(Memory_Tracker));
  memory_tracker.check_addr_queue = create_swsr_ring_buffer(ADDR_QUEUE_SZ);
  if (!memory_tracker.check_addr_queue.buffer) {
    printf("Failed to intialize ring buffer for check address queue.\n");
    return FALSE;
  }
  memory_tracker.event_queue = create_swsr_ring_buffer(KB(64));
  if (!memory_tracker.event_queue.buffer) {
    printf("Failed to intialize ring buffer for check address queue.\n");
    return FALSE;
  }

  // Kind of arbitrary numbers, but really we could just reserve an absurdly huge number here
  memory_tracker.processes = create_garr(Process, 0x10000, 0x1000);
  memory_tracker.process_names = create_garr(Process_Name, 0x10000, 0x1000);
  memory_tracker.processes_memory = create_garr(Process_Memory, 0x20000, 0x1000);

  return memory_tracker_initialize_processes(&memory_tracker);
}

void CALLBACK etw_event_callback(EVENT_RECORD* Event) {
  Memory_Tracker *mt = &memory_tracker;
  const GUID* provider_guid = &Event->EventHeader.ProviderId;
  UCHAR opcode = Event->EventHeader.EventDescriptor.Opcode;
  EventKind event_kind = Fu_DontCare;

  if      (IsEqualGUID(provider_guid, &Fu_StackWalkGuid) && opcode == 32) event_kind = Fu_StackWalkEvent;
  else if (IsEqualGUID(provider_guid, &Fu_LbrGuid)       && opcode == 32) event_kind = Fu_LbrStackWalkEvent;
  else if (IsEqualGUID(provider_guid, &Fu_PageFaultGuid) && opcode == 98) event_kind = Fu_VirtualAllocEvent;
  else if (IsEqualGUID(provider_guid, &Fu_ProcessGuid)) {
    if      (opcode == 1) event_kind = Fu_ProcessStartEvent;
    else if (opcode == 2) event_kind = Fu_ProcessEndEvent;
    else return;
  }
  else {
    // WCHAR buf[255] = {0};
    // StringFromGUID2(provider_guid, buf, 255);
    // printf("[%u] %S +%u\n", opcode, buf, Event->UserDataLength);
    return;
  }

  if (event_kind >= Fu_ProcessStartEvent && Event->UserData) {
    if ((event_kind == Fu_ProcessStartEvent || event_kind == Fu_ProcessEndEvent) && Event->UserDataLength >= sizeof(Event_Header)) {
      ETW_Event_Process *pse = (ETW_Event_Process*)Event->UserData;
      if (pse->ProcessId == 0 || pse->ProcessId == 4) return;
      swsr_check_write_size(&mt->event_queue, sizeof(Event_Header));
      swsr_write(&mt->event_queue, &(Event_Header){event_kind, pse->ProcessId}, sizeof(Event_Header));
    }
    else if (event_kind == Fu_VirtualAllocEvent && Event->UserDataLength >= sizeof(EWT_Event_Virtual_Alloc)) {
      EWT_Event_Virtual_Alloc *vae = (EWT_Event_Virtual_Alloc*)Event->UserData;
      if (vae->ProcessId == 0 || vae->ProcessId == 4) return;
      swsr_check_write_size(&mt->event_queue, sizeof(Event_Virtual_Alloc));
      swsr_write(&mt->event_queue, &(Event_Virtual_Alloc){{event_kind, vae->ProcessId}, vae->BaseAddress, vae->RegionSize}, sizeof(Event_Virtual_Alloc));
    }
    else return;
    // else if TI events here...
    swsr_commit_write(&mt->event_queue);
    return;
  }

  // Going to skip event correlation and just stick with 
  // looking at events that also provide a PID.

	// UCHAR CpuIndex = GetEventProcessorIndex(Event);

  if (Event->UserData && Event->UserDataLength > sizeof(ETW_Event_Stack_Walk)) {
    ETW_Event_Stack_Walk *lbr_data = (ETW_Event_Stack_Walk*)Event->UserData;
    if (lbr_data->StackProcess == 0 || lbr_data->StackProcess == 4) return;
    DWORD num_addresses = (Event->UserDataLength - sizeof(ETW_Event_Stack_Walk)) / sizeof(DWORD64);
    // Because the Lbr stackwalk header seems to have 1 extra DWORD64
    DWORD skip_addr = 0;
    if (event_kind == Fu_LbrStackWalkEvent) {
      skip_addr = 1;
    }
    num_addresses -= skip_addr;
    DWORD total_size = num_addresses * sizeof(DWORD64) + sizeof(Addresses_To_Check);
    BOOL can_write = swsr_check_write_size(&mt->check_addr_queue, total_size);
    if (!can_write) {
      //printf("Dropping LBR event data, queue was full. count: %u count+sz: %u\n", count, count+total_size);
      mt->addrs_dropped += num_addresses;
    }
    else {
      //printf("+ PID(%u) 0x%p #%u Count: %u + %u\n", lbr_data->StackProcess, mt->check_addr_tail, num_addresses, count, total_size);
      swsr_write(&mt->check_addr_queue, &lbr_data->StackProcess, sizeof(DWORD));
      swsr_write(&mt->check_addr_queue, &num_addresses, sizeof(DWORD));
      swsr_write(&mt->check_addr_queue, lbr_data->Stack + skip_addr, sizeof(DWORD64) * num_addresses);
      swsr_commit_write(&mt->check_addr_queue);
      WakeByAddressSingle(&mt->check_addr_queue.count);
      mt->addrs_added += num_addresses;
    }
  }
}

DWORD CALLBACK process_thread(LPVOID arg) {
	TRACEHANDLE session = (TRACEHANDLE)arg;
	ProcessTrace(&session, 1, NULL, NULL);
	return 0;
}

// Thanks Prelude:
void main(int argc, char*argv[]) {
  DWORD status = 0; 
  HANDLE token = INVALID_HANDLE_VALUE;
  BOOL got_token = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token);
  printf("Got Token: %s\n", got_token ? "Yes" : "No");
  BOOL is_set = set_privilege(token, "SeSystemProfilePrivilege", TRUE);
  printf("Set PROFILE Priv: %s\n", is_set ? "Yes": "No");

  if (!got_token || !is_set) return;

  struct {
		EVENT_TRACE_PROPERTIES_V2 properties;
		WCHAR name[1024];
	} trace;

	const WCHAR trace_name[] = L"Fugue";

	EVENT_TRACE_PROPERTIES_V2* properties = &trace.properties;

	// stop existing trace in case it is already running
	ZeroMemory(&trace, sizeof(trace));
	properties->Wnode.BufferSize = sizeof(trace);
	properties->LoggerNameOffset = sizeof(trace.properties);

	status = ControlTraceW(0, trace_name, (EVENT_TRACE_PROPERTIES*)properties, EVENT_TRACE_CONTROL_STOP);
	if (!(status == ERROR_SUCCESS || status == ERROR_MORE_DATA || status == ERROR_WMI_INSTANCE_NOT_FOUND)) {
    printf("Failed to conrolTrace (for initital stop.). Error: 0x%8x\n", status);
    return;
  }

  DWORD num_seconds_to_run = 60;
  if (argc > 1 && argv[1][0] == 's') {
    return;
  } else if (argc > 1) {
    char *temp = NULL;
    num_seconds_to_run = strtoul(argv[1], &temp, 10);
    if (!num_seconds_to_run) num_seconds_to_run = 60;
  }
  printf("Running for %u seconds.\n", num_seconds_to_run);


  memory_tracker_init();


  HANDLE mt_thread = CreateThread(NULL, 0, &memory_tracker_thread, (LPVOID)&memory_tracker, 0, NULL);
  if (mt_thread == NULL || mt_thread == INVALID_HANDLE_VALUE) {
    printf("Failed to create mem manager thread. 0x%08x\n", GetLastError());
  }

	// start a new trace, capture context switches
	ZeroMemory(&trace, sizeof(trace));
	properties->Wnode.BufferSize = sizeof(trace);
	properties->Wnode.ClientContext = 1;
	properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID | WNODE_FLAG_VERSIONED_PROPERTIES;
	properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
	properties->VersionNumber = 2;
	properties->EnableFlags = EVENT_TRACE_FLAG_PROFILE | EVENT_TRACE_FLAG_CSWITCH | EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_VIRTUAL_ALLOC;
	// properties->EnableFlags = EVENT_TRACE_FLAG_CSWITCH;// | EVENT_TRACE_FLAG_INTERRUPT | EVENT_TRACE_FLAG_PROFILE | EVENT_TRACE_FLAG_PROCESS_COUNTERS;
	properties->LoggerNameOffset = sizeof(trace.properties);

	TRACEHANDLE trace_handle;
	status = StartTraceW(&trace_handle, trace_name, (EVENT_TRACE_PROPERTIES*)properties);
	if (status != ERROR_SUCCESS) {
    printf("Failed to start trace. 0x%8x\n", status);
    return;
	}
	else {
    // Timer interval
    // TODO: should probably actually query the counters, and get the min/max Interval values and find the counters "Source" by Name.
    TRACE_PROFILE_INTERVAL interval = {0};
    interval.Source = 0x0;
    interval.Interval = 1221; // 121.1 microseconds
    //interval.Interval = 1000000; // 1 second
    if (TRUE) {
      DWORD intervals[] = {interval.Source};
      status = TraceSetInformation(0, TraceSampledProfileIntervalInfo, &interval, sizeof(TRACE_PROFILE_INTERVAL));
      if (ERROR_SUCCESS != status) {
        printf("Failed to set interval info. 0x%08x\n", status);
      }
      status = TraceSetInformation(0, TraceProfileSourceConfigInfo, intervals, sizeof(intervals));
      if (ERROR_SUCCESS != status) {
        printf("Failed to set source info. 0x%08x\n", status);
      }
    }

    if (TRUE) {
      DWORD lbr_config = (FilterKernel | FilterJcc | FilterNearRelCall | FilterNearRelJmp);

      status = TraceSetInformation(
       trace_handle,
       TraceLbrConfigurationInfo,
       &lbr_config,
       sizeof(lbr_config));
      if (ERROR_SUCCESS != status) {
        printf("Failed to set Lbr config event info. 0x%08x\n", status);
      }

      DWORD hook_ids[1] = {0};
      //DWORD PmcInterrupt = 0x0F00 | 0x2F;
      hook_ids[0] = 0x0524;//CSWITCH_HOOK_ID; // 0x0524 (1316)
      //hook_ids[1] = PmcInterrupt;
      status = TraceSetInformation(
       trace_handle,
       TraceLbrEventListInfo,
       hook_ids,
       sizeof(hook_ids));
      if (ERROR_SUCCESS != status) {
        printf("Failed to set Lbr event info. 0x%08x\n", status);
      }
    }

    // Enable stack traces for CSwitch to get Lbr.
    // This also needs to be configured for SampleProfile so when our Timer counter overflow(?) occurs
    //  then we will also get the LBR data dumped. Which is nice.
    if (TRUE) {
      CLASSIC_EVENT_ID sample_ev = {0}; 
      sample_ev.EventGuid = Fu_PerfInfoGuid; 
      sample_ev.Type = 46; // SampleProfile 

      CLASSIC_EVENT_ID cswitch_ev = {0}; 
      cswitch_ev.EventGuid = Fu_ThreadGuid; 
      cswitch_ev.Type = 36; // CSwitch 

      CLASSIC_EVENT_ID events[] = {sample_ev, cswitch_ev};

      status = TraceSetInformation(trace_handle, TraceStackTracingInfo, events, sizeof(events));
      if (ERROR_SUCCESS != status) {
        printf("Failed to set source info. 0x%08x\n", status);
        return;
      }
    }

    // So I don't think this needs to be done
    // And I've tested without it but the timer seems to trigger less consistently.
    // TODO: I should actually look into this at somepoint.
    if (TRUE) {
			status = TraceSetInformation(trace_handle, TracePmcCounterListInfo, &interval.Source, sizeof(DWORD));
			// if this triggers ERROR_BUSY = 0xaa, then I believe that that someone else is collecting PMU counters
			// in the system, and I'm not sure how or if at all you to forcefully stop/reconfigure it. Rebooting helps.
			if (status != ERROR_SUCCESS) {
        printf("Failed to set CounterListInfo. 0x%08x\n", status);
      }

			// On interval set for Timer, we want this Sample Event to be logged.. with Extended info?
			CLASSIC_EVENT_ID sameple_ev = { Fu_PerfInfoGuid, 46 };
			status = TraceSetInformation(trace_handle, TracePmcEventListInfo, &sameple_ev, sizeof(sameple_ev));
			if (status != ERROR_SUCCESS) {
        printf("Failed to set EventListInfo. 0x%08x\n", status);
      }
    }
   
    // I think this is correct but can't really confirm
    // because apparently the laptop I'm using is ancient
    // and the CPU does not support IPT. Which is sad...
    if (FALSE) {
      Event_Trace_IPT_Config_Info ipt_config = {0};
      ipt_config.EventTraceInformationClass = EventTraceProcessorTraceConfigurationInformation;
      ipt_config.TraceHandle = trace_handle;
      ipt_config.IptOptions.TraceMode = 1;
      ipt_config.IptOptions.TimeMode = IptNoTimingPackets;
      ipt_config.IptOptions.MTCFreq = 0;
      ipt_config.IptOptions.BufferSize = KB(4);
      ipt_config.IptOptions.TraceSessionMode = IptMatchByAnyApp;
      ipt_config.IptOptions.TraceCodeMode = IptRegUserModeOnly;
      status = NtSetSystemInformation(SystemPerformanceTraceInformation, &ipt_config, sizeof(ipt_config));
      printf("Set Ipt Config info: 0x%08x\n", status);
      Event_Trace_Ipt_List_Info ipt_events= {0};
      ipt_events.EventTraceInformationClass = EventTraceProcessorTraceEventListInformation;
      ipt_events.HookIds[0] = 1316; // CSWITCH
      status = NtSetSystemInformation(SystemPerformanceTraceInformation, &ipt_events, sizeof(ipt_events));
      printf("Set Ipt hook info: 0x%08x\n", status);
    }
	
    EVENT_TRACE_LOGFILEW log;
		ZeroMemory(&log, sizeof(log));
    log.LoggerName = trace.name;
		log.EventRecordCallback = etw_event_callback;
		log.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP | PROCESS_TRACE_MODE_REAL_TIME;
		//log.Context = &context;

		// open trace for processing incoming events
		TRACEHANDLE session = OpenTraceW(&log);
		if (session == INVALID_PROCESSTRACE_HANDLE) {
      printf("Invalid process trace handle. OpenTraceFailed with: 0x%8x\n", GetLastError());
    }

    HANDLE processing_thread = CreateThread(NULL, 0, &process_thread, (LPVOID)session, 0, NULL);
    if (processing_thread == NULL || processing_thread == INVALID_HANDLE_VALUE) {
      printf("Failed to create process trace thread. 0x%08x\n", status);
    }

    DWORD wait = WaitForSingleObject(processing_thread, 1000 * num_seconds_to_run);
    // stop producing new events
    status = ControlTraceW(trace_handle, NULL, (EVENT_TRACE_PROPERTIES*)properties, EVENT_TRACE_CONTROL_STOP);
    // closes trace processing, this will make ETW to process all the pending events in buffers
    status = CloseTrace(session);
    // Idk I guess we'll give the thread a few seconds to finished up
    Sleep(1000 * 2);

    if (wait == WAIT_TIMEOUT) {
      if (!TerminateThread(processing_thread, 1)) {
        printf("Failed to terminate etw processing_thread thread. 0x%08x\n", GetLastError());
      }
    }
    if (!TerminateThread(mt_thread, 1)) {
      printf("Failed to terminate memory tracker thread. 0x%08x\n", GetLastError());
    }

    // so scuffed
    printf("Final tally: Addrs Added: %llu Addrs Checked: %llu Addrs Dropped: %llu\n", memory_tracker.addrs_added, memory_tracker.addrs_checked, memory_tracker.addrs_dropped);
    printf("Hit Rate: %.2f%\n", (float)(memory_tracker.addrs_checked/10000)/ (float)((memory_tracker.addrs_added + memory_tracker.addrs_dropped)/10000)*100);

    Process *processes = (Process*)memory_tracker.processes.address;
    for (DWORD i = 0; i < memory_tracker.num_processes; i++) {
      Process *proc = processes + i;
      if (proc->pid == 0) continue;
      print_process_stats(proc);
    }

    printf("Done.\n");
  }
}