// Write Usage:
//  - check max size you want to write first:
//    - swsr_check_write_size
//  - write as many times up to max size (there is no error for writing more)
//    - swsr_write
//  - commit the write
//    - swsr_commit_write
// Read Usage:
//  - try to read some amount of bytes, internally keeps track of reads count
//    - swsr_try_read
//  - commit the reads
//    - swsr_commit_read
// Max size is 4GB -- MAX_DWORD
typedef struct tag_single_writer_single_reader_ring_buf {
  PBYTE head;
  PBYTE tail;
  DWORD count; // this is not descriptive..
  DWORD cur_write_count;
  DWORD cur_read_count;
  DWORD size;
  PBYTE buffer;
  LPVOID secondary_view; // for cleanup
} SWSR_Ring_Buffer;

// Ty msdn
void* CreateRingBuffer (unsigned int bufferSize, _Outptr_ void** secondaryView ) {
  BOOL result;
  HANDLE section = NULL;
  SYSTEM_INFO sysInfo;
  void* ringBuffer = NULL;
  void* placeholder1 = NULL;
  void* placeholder2 = NULL;
  void* view1 = NULL;
  void* view2 = NULL;

  GetSystemInfo (&sysInfo);

  if ((bufferSize % sysInfo.dwAllocationGranularity) != 0) {
    return NULL;
  }

  placeholder1 = (PCHAR) VirtualAlloc2 (
    NULL,
    NULL,
    2 * bufferSize,
    MEM_RESERVE | MEM_RESERVE_PLACEHOLDER,
    PAGE_NOACCESS,
    NULL, 0
  );

  if (placeholder1 == NULL) {
    printf ("VirtualAlloc2 failed, error %#x\n", GetLastError());
    goto Exit;
  }

  result = VirtualFree (
    placeholder1,
    bufferSize,
    MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER
  );

  if (result == FALSE) {
    printf ("VirtualFreeEx failed, error %#x\n", GetLastError());
    goto Exit;
  }

  placeholder2 = (void*) ((ULONG_PTR) placeholder1 + bufferSize);

  section = CreateFileMapping (
    INVALID_HANDLE_VALUE,
    NULL,
    PAGE_READWRITE,
    0,
    bufferSize, NULL
  );

  if (section == NULL) {
    printf ("CreateFileMapping failed, error %#x\n", GetLastError());
    goto Exit;
  }

  view1 = MapViewOfFile3 (
    section,
    NULL,
    placeholder1,
    0,
    bufferSize,
    MEM_REPLACE_PLACEHOLDER,
    PAGE_READWRITE,
    NULL, 0
  );

  if (view1 == NULL) {
    printf ("MapViewOfFile3 failed, error %#x\n", GetLastError());
    goto Exit;
  }

  placeholder1 = NULL;

  view2 = MapViewOfFile3 (
    section,
    NULL,
    placeholder2,
    0,
    bufferSize,
    MEM_REPLACE_PLACEHOLDER,
    PAGE_READWRITE,
    NULL, 0
  );

  if (view2 == NULL) {
    printf ("MapViewOfFile3 failed, error %#x\n", GetLastError());
    goto Exit;
  }

  ringBuffer = view1;
  *secondaryView = view2;

  placeholder2 = NULL;
  view1 = NULL;
  view2 = NULL;

Exit:

  if (section != NULL) {
    CloseHandle (section);
  }

  if (placeholder1 != NULL) {
    VirtualFree (placeholder1, 0, MEM_RELEASE);
  }

  if (placeholder2 != NULL) {
    VirtualFree (placeholder2, 0, MEM_RELEASE);
  }

  if (view1 != NULL) {
    UnmapViewOfFileEx (view1, 0);
  }

  if (view2 != NULL) {
    UnmapViewOfFileEx (view2, 0);
  }

  return ringBuffer;
}

SWSR_Ring_Buffer create_swsr_ring_buffer(DWORD size) {
  SWSR_Ring_Buffer furb = {0};
  furb.buffer = (PBYTE)CreateRingBuffer(size, &furb.secondary_view);
  if (!furb.buffer) return furb;
  furb.size = size;
  furb.head = furb.buffer;
  furb.tail = furb.buffer;
  return furb;
}

BOOL swsr_check_write_size(SWSR_Ring_Buffer *rb, DWORD len) {
  DWORD count = InterlockedAdd(&rb->count, 0);
  return (count + len < rb->size);
}

// assumes user has already used check_write_size before calling
void swsr_write(SWSR_Ring_Buffer *rb, PBYTE data, DWORD len) {
  memcpy(rb->tail + rb->cur_write_count, data, len);
  rb->cur_write_count += len;
}

void swsr_commit_write(SWSR_Ring_Buffer *rb) {
  DWORD64 tail = InterlockedAdd64(&rb->tail, rb->cur_write_count);
  if (tail >= rb->buffer + rb->size) {
    InterlockedAdd64(&rb->tail, -((LONG64)rb->size));
  }
  InterlockedAdd(&rb->count, rb->cur_write_count);
  rb->cur_write_count = 0;
}

PBYTE swsr_try_read(SWSR_Ring_Buffer *rb, DWORD len) {
  DWORD count = InterlockedAdd(&rb->count, 0);
  if ((count - rb->cur_read_count) < len) return NULL;
  PBYTE retval = rb->head + rb->cur_read_count;
  rb->cur_read_count += len;
  return retval;
}

void swsr_commit_read(SWSR_Ring_Buffer *rb) {
  InterlockedAdd(&rb->count, -((LONG)rb->cur_read_count));
  DWORD64 head = InterlockedAdd64(&rb->head, rb->cur_read_count);
  rb->cur_read_count = 0;
  if (head >= rb->buffer + rb->size) {
    InterlockedAdd64(&rb->head, -((LONG64)rb->size));
  }
}

void swsr_revert_read(SWSR_Ring_Buffer *rb) {
  rb->cur_read_count = 0;
}