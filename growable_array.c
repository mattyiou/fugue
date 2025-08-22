// Growable Array usage:
// I guess this is more like an arena than array but its okay.
//
// growable_array = create_garr(Type_Of_Array_Item, Max_Items, Intitial_Num_Items)
//  - we commit memory for Initial_Num_Items
//  - we reserve memory for Max_Items
//
// Item = new_item_growable_array(&growable_array)
// Item->something = whatever
//
// release_item_growable_array(&growable_array, Item)

typedef struct tag_growable_array_item {
  LPVOID next;
  // ... etc ...
} Growalble_Array_Item;

typedef struct tag_growable_array {
  PBYTE address;
  DWORD64 reserved;
  DWORD64 committed;
  DWORD64 used;
  DWORD type_sz;
  Growalble_Array_Item *freelist;
} Growable_Array;

Growable_Array create_growable_array(DWORD64 reserve, DWORD64 commit, DWORD type_sz) {
  Growable_Array garr = {0};
  reserve = PAGE_ROUND_UP(reserve);
  commit = PAGE_ROUND_UP(commit);

  if (reserve < commit) return garr;
  if (commit < KB(8)) commit = KB(8);

  garr.address = VirtualAlloc(NULL, reserve, MEM_RESERVE, PAGE_NOACCESS);
  if (garr.address) {
    LPVOID committed = VirtualAlloc(garr.address, commit, MEM_COMMIT, PAGE_READWRITE);
    if (!committed) {
      VirtualFree(garr.address, 0, MEM_RELEASE);
      garr.address = NULL;
    } else {
      garr.reserved = reserve;
      garr.committed = commit;
      garr.type_sz = type_sz;
    }
  }
  return garr;
}

LPVOID new_item_growable_array(Growable_Array *garr) {
  if (garr->freelist) {
    Growalble_Array_Item *item = garr->freelist;
    garr->freelist = item->next;
    item->next = NULL;
    return item;
  }

  if (garr->used + garr->type_sz <= garr->committed) {
    LPVOID item = garr->address + garr->used;
    garr->used += garr->type_sz;
    return item;
  }
  else if (garr->used + garr->type_sz > garr->reserved) {
    return NULL;
  }

  // Make room for bunch more
  DWORD64 grow_size = garr->committed / 2;
  grow_size = PAGE_ROUND_UP(grow_size);
  if (garr->committed + grow_size > garr->reserved) {
    grow_size = garr->reserved - garr->committed;
  }
  if (grow_size == 0) {
    return NULL;
  }

  LPVOID did_grow = VirtualAlloc(garr->address + garr->committed, grow_size, MEM_COMMIT, PAGE_READWRITE);
  if (did_grow && garr->used + garr->type_sz <= garr->committed) {
    LPVOID item = garr->address + garr->used;
    garr->used += garr->type_sz;
    return item;
  }

  return NULL;
}

void release_item_growable_array(Growable_Array *garr, Growalble_Array_Item *item) {
  if (garr->address > item || item >= garr->address + garr->reserved) {
    printf("Attempted to release item to a garr that it doesn't belong to!\n");
    // assert(FALSE, "Attempted to release item to a garr that it doesn't belong to!\n");
    return;
  }
  SecureZeroMemory(item, garr->type_sz);
  item->next = garr->freelist;
  garr->freelist = item->next;
}

#define create_garr(type, max, initial) create_growable_array(sizeof(type)*max, sizeof(type)*initial, sizeof(type))

