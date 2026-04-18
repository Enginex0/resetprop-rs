# AOSP Android 15 Property System Reference — Seal Implementation

**Purpose**: Dense, citation-heavy reference for ptrace-based MAP_PRIVATE sealing of init's property arena mappings and __system_property_update hook installation.

---

## 1. prop_info Layout & Serial Encoding

### C++ Structure
```c++
struct prop_info {
  atomic_uint_least32_t serial;           // +0 bytes, 4 bytes
  union {
    char value[PROP_VALUE_MAX];           // +4 bytes, 92 bytes
    struct {
      char error_message[56];             // +4 bytes, 56 bytes
      uint32_t offset;                    // +60 bytes, 4 bytes
    } long_property;
  };
  char name[0];                           // +96 bytes (flexible)
};
```
**Static assertion**: `sizeof(prop_info) == 96` (prop_info.h:89)

### Rust Constants
```rust
pub const PROP_INFO_SIZE: usize = 96;
pub const PROP_INFO_SERIAL_OFFSET: usize = 0;
pub const PROP_INFO_VALUE_OFFSET: usize = 4;
pub const PROP_VALUE_MAX: usize = 92;
pub const PROP_INFO_NAME_OFFSET: usize = 96;

pub const LONG_FLAG: u32 = 1 << 16;  // kLongFlag (prop_info.h:48)
pub const LONG_LEGACY_ERROR_BUFFER_SIZE: usize = 56;  // kLongLegacyErrorBufferSize (prop_info.h:55)
```

### Serial Field Bitfield
```
Bit 0:     DIRTY — marks in-flight update (SERIAL_DIRTY macro, system_properties.cpp:52)
Bits 1-15: Reserved
Bit 16:    LONG_FLAG — indicates value stored at offset, not inline (prop_info.h:48)
Bits 17-23: Reserved
Bits 24-31: VALUE_LENGTH — top byte encodes actual value length (SERIAL_VALUE_LEN macro, system_properties.cpp:53)
```

### Rust Serial Helpers
```rust
pub const fn serial_dirty(serial: u32) -> bool {
    serial & 1 != 0
}

pub const fn serial_value_len(serial: u32) -> u32 {
    serial >> 24
}

pub const fn serial_long_flag(serial: u32) -> bool {
    (serial & (1 << 16)) != 0
}
```

---

## 2. prop_area Layout & Magic

### C++ Structure
```c++
class prop_area {
  uint32_t bytes_used_;                   // +0 bytes
  atomic_uint_least32_t serial_;          // +4 bytes (global change counter)
  uint32_t magic_;                        // +8 bytes
  uint32_t version_;                      // +12 bytes
  uint32_t reserved_[28];                 // +16 to +128 bytes
  char data_[0];                          // +128 bytes (flexible)
};
```

### Constants
```c++
constexpr uint32_t PROP_AREA_MAGIC = 0x504f5250;    // "PROP" (prop_area.cpp:49)
constexpr uint32_t PROP_AREA_VERSION = 0xfc6ed0ab;  // (prop_area.cpp:50)
constexpr size_t PA_SIZE = 128 * 1024;              // Default 128 KB (prop_area.cpp:47)
```

### Rust Constants
```rust
pub const PROP_AREA_MAGIC: u32 = 0x504f5250;
pub const PROP_AREA_VERSION: u32 = 0xfc6ed0ab;
pub const PA_SIZE: usize = 128 * 1024;
pub const PA_HEADER_SIZE: usize = 128;  // bytes_used_ + serial_ + magic_ + version_ + reserved_

pub const fn dirty_backup_area_offset() -> usize {
    std::mem::size_of::<prop_trie_node>()  // Root trie node at +128
}
```

---

## 3. SystemProperties::Update — Full Call Trace

**Entry point**: system_properties.cpp:270–336, invoked via `__system_property_update()` (system_property_set.cpp:418)

**Call sequence with citations**:

1. **Line 270-277**: Parameter validation (len < PROP_VALUE_MAX, initialized check)

2. **Line 278**: Check for appcompat override contexts
   ```cpp
   bool have_override = appcompat_override_contexts_ != nullptr;
   ```

3. **Line 280-285**: Obtain serial prop_area (global update notifier)
   ```cpp
   prop_area* serial_pa = contexts_->GetSerialPropArea();
   prop_area* override_serial_pa = have_override ? appcompat_override_contexts_->GetSerialPropArea() : nullptr;
   ```

4. **Line 286-293**: Get property area and optional override area for this property name

5. **Line 297-298**: Load current serial (dirty bit + length)
   ```cpp
   uint32_t serial = atomic_load_explicit(&pi->serial, memory_order_relaxed);
   unsigned int old_len = SERIAL_VALUE_LEN(serial);
   ```

6. **Line 304-307**: Copy old value to dirty backup area (ensures readers see consistent data)
   ```cpp
   memcpy(pa->dirty_backup_area(), pi->value, old_len + 1);
   if (have_override) {
     memcpy(override_pa->dirty_backup_area(), override_pi->value, old_len + 1);
   }
   ```
   **Critical**: dirty_backup_area() is at prop_area::data_ + sizeof(prop_trie_node) (prop_area.h:139)

7. **Line 308**: Memory fence (release) — readers will see backup before dirty bit
   ```cpp
   atomic_thread_fence(memory_order_release);
   ```

8. **Line 309-310**: Set dirty bit (signals readers to use backup)
   ```cpp
   serial |= 1;
   atomic_store_explicit(&pi->serial, serial, memory_order_relaxed);
   ```

9. **Line 311-315**: Copy new value into pi->value (or override_pi->value)
   ```cpp
   strlcpy(pi->value, value, len + 1);
   if (have_override) {
     atomic_store_explicit(&override_pi->serial, serial, memory_order_relaxed);
     strlcpy(override_pi->value, value, len + 1);
   }
   ```
   **Addresses touched**: pi->value (offset +4 in prop_info) and override_pi->value

10. **Line 318**: Memory fence (release) — new value is visible
    ```cpp
    atomic_thread_fence(memory_order_release);
    ```

11. **Line 319-323**: Compute and store new serial (length shifted to top byte, dirty bit cleared)
    ```cpp
    int new_serial = (len << 24) | ((serial + 1) & 0xffffff);
    atomic_store_explicit(&pi->serial, new_serial, memory_order_relaxed);
    if (have_override) {
      atomic_store_explicit(&override_pi->serial, new_serial, memory_order_relaxed);
    }
    ```

12. **Line 324**: Wake any readers polling on pi->serial via futex
    ```cpp
    __futex_wake(&pi->serial, INT32_MAX);
    ```

13. **Line 325-327**: Bump global serial (signals system-wide property change)
    ```cpp
    atomic_store_explicit(serial_pa->serial(),
                          atomic_load_explicit(serial_pa->serial(), memory_order_relaxed) + 1,
                          memory_order_release);
    ```

14. **Line 328-332**: If appcompat override, bump its serial too
    ```cpp
    if (have_override) {
      atomic_store_explicit(override_serial_pa->serial(), ..., memory_order_release);
    }
    ```

15. **Line 333**: Wake system-wide waiters
    ```cpp
    __futex_wake(serial_pa->serial(), INT32_MAX);
    ```

### MAP_PRIVATE Coverage
**All addresses modified in Update() are within pi (prop_info) or dirty_backup_area():**
- `pi->serial` (offset 0 in prop_info)
- `pi->value` (offset 4 in prop_info)
- `pa->dirty_backup_area()` (offset 128 + sizeof(prop_trie_node) in prop_area)
- `override_pi->serial`, `override_pi->value`, `override_pa->dirty_backup_area()` (same offsets in override area)

**Consequence**: A file-level `MAP_PRIVATE | MAP_FIXED` remap of init's property area + appcompat override area mapping to a private copy will isolate all these writes. New writes by init go to private copy; old (pre-seal) data and other processes' reads remain on the original shared file.

---

## 4. SystemProperties::Add — Property Creation

**Entry**: system_properties.cpp:338–401

- Called when property does not exist (line 420 in property_service.cpp)
- Validates name length (≥1), value length (< PROP_VALUE_MAX unless ro.* property)
- Calls `pa->add(name, namelen, value, valuelen)` (prop_area.cpp:369–372)
- `pa->add()` invokes `find_property(root_node(), name, namelen, value, valuelen, true)` with `alloc_if_needed=true`

### find_property (prop_area.cpp:278–334)
- Walks trie by '.' delimiters: "ro.secure" → "ro" → "secure"
- At each trie node, binary-searches left/right subtree for matching name
- If found, returns existing prop_info
- If not found and `alloc_if_needed=true`, allocates new prop_trie_node or prop_info via `allocate_obj()` and links via atomic store with memory_order_release

**Appcompat mirror** (system_properties.cpp:379–400):
- If appcompat_override_contexts_ exists and property name starts with "ro.appcompat_override.", also adds to override area
- Updates override area's serial via atomic_store_explicit (line 392–395)

---

## 5. SystemProperties::Find — Property Lookup

**Entry**: system_properties.cpp:162–174

```cpp
const prop_info* SystemProperties::Find(const char* name) {
  prop_area* pa = contexts_->GetPropAreaForName(name);
  return pa->find(name);  // pa->find() calls find_property(..., alloc_if_needed=false)
}
```

### prop_area::find (prop_area.cpp:365–367)
```cpp
const prop_info* prop_area::find(const char* name) {
  return find_property(root_node(), name, strlen(name), nullptr, 0, false);
}
```

Trie walk with `alloc_if_needed=false`: returns nullptr if property not found (no allocations).

---

## 6. __system_property_update — libc Export

**Location**: system_property_set.cpp (no direct __system_property_update export visible; dispatched via __system_property_find + SystemProperties::Update)

**Called from init**: property_service.cpp:418
```cpp
prop_info* pi = (prop_info*)__system_property_find(name.c_str());
if (pi != nullptr) {
  __system_property_update(pi, value.c_str(), valuelen);
}
```

**Arm64 ABI** (typical libc implementation):
- x0 = prop_info* (address of prop_info struct)
- x1 = const char* (new value string)
- w2 = unsigned int (value length)
- Return w0 = int (0 on success, -1 on error)

**Internal dispatch**: libc's __system_property_update likely calls SystemProperties::Update() after finding the global instance.

---

## 7. prop_area::map_prop_area_rw — RW Mapping

**Location**: prop_area.cpp:55–109

```cpp
prop_area* prop_area::map_prop_area_rw(const char* filename, const char* context,
                                       bool* fsetxattr_failed) {
  const int fd = open(filename, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_EXCL, 0444);
  // Open flags: O_RDWR, O_CREAT, O_NOFOLLOW, O_CLOEXEC, O_EXCL (line 60)
  // File created with mode 0444 (read-only) (line 60)
  
  if (errno == EACCES) abort();  // Line 63–68
  
  // Optional SELinux xattr (line 72–89)
  if (context) {
    fsetxattr(fd, XATTR_NAME_SELINUX, context, strlen(context) + 1, 0);
  }
  
  ftruncate(fd, PA_SIZE);  // Line 91
  
  void* const memory_area = mmap(nullptr, pa_size_, 
                                 PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);  // Line 99
  
  prop_area* pa = new (memory_area) prop_area(PROP_AREA_MAGIC, PROP_AREA_VERSION);
  close(fd);
  return pa;
}
```

**Key points**:
- File created O_EXCL (fails if exists)
- Mapped MAP_SHARED initially (all processes see same data)
- Init-only function (called during property_service initialization)

---

## 8. prop_area::map_fd_ro — Read-Only Validation

**Location**: prop_area.cpp:111–138

```cpp
prop_area* prop_area::map_fd_ro(const int fd) {
  struct stat fd_stat;
  fstat(fd, &fd_stat);
  
  // Reject if not owned by root (uid 0) and not world-writable
  if ((fd_stat.st_uid != 0) || (fd_stat.st_gid != 0) ||
      ((fd_stat.st_mode & (S_IWGRP | S_IWOTH)) != 0) ||
      (fd_stat.st_size < static_cast<off_t>(sizeof(prop_area)))) {
    return nullptr;  // Line 117–121
  }
  
  void* const map_result = mmap(nullptr, pa_size_, 
                                PROT_READ, MAP_SHARED, fd, 0);  // Line 126
  
  // Validate magic and version
  if ((pa->magic() != PROP_AREA_MAGIC) || (pa->version() != PROP_AREA_VERSION)) {
    munmap(pa, pa_size_);
    return nullptr;
  }
  
  return pa;
}
```

**Callout**: Readers use this validation. If seal modifies file permissions (chmod), readers will reject the file. **Do not chmod the property area file.**

---

## 9. Init Property Service Flow

**Location**: system/core/init/property_service.cpp

### PropertySet (line 391–441)
Called when property setprop request arrives (socket or direct):

1. Validate property name and value (lines 395–403)
2. If property exists: call `__system_property_update(pi, value, len)` (line 418)
3. If property doesn't exist: call `__system_property_add(name, name.size(), value, valuelen)` (line 420)
4. If property starts with "persist." or "next_boot.", queue async disk write (line 429–435)
5. Notify property change via PropertyChanged() (line 439)
6. Return PROP_SUCCESS or error code

### CheckMacPerms (line 177–191)
Called before PropertySet to validate SELinux permissions:

```cpp
static bool CheckMacPerms(const std::string& name, const char* target_context,
                          const char* source_context, const ucred& cr) {
  auto lock = std::lock_guard{selinux_check_access_lock};
  return selinux_check_access(source_context, target_context, "property_service", "set",
                              &audit_data) == 0;
}
```

**Key point**: SELinux check happens at property_service level. A ptrace-installed hook in libc cannot intercept or block this check — it occurs before the hook is even called. The hook only modifies the shared-memory update; policy is enforced upstream.

### Error Codes
Defined in sys/_system_properties.h (referenced system_property_set.cpp:262–272):
```
PROP_ERROR_READ_CMD             = 1
PROP_ERROR_READ_DATA            = 2
PROP_ERROR_READ_ONLY_PROPERTY   = 3
PROP_ERROR_INVALID_NAME         = 4
PROP_ERROR_INVALID_VALUE        = 5
PROP_ERROR_PERMISSION_DENIED    = 6
PROP_ERROR_INVALID_CMD          = 7
PROP_ERROR_HANDLE_CONTROL_MESSAGE = 8
PROP_ERROR_SET_FAILED           = 9
PROP_SUCCESS                    = 0
```

---

## 10. Appcompat Override — Mirror Writes

**Location**: system_properties.cpp:278–332

### Initialization (system_properties.cpp:123–134)
```cpp
appcompat_filename_ = PropertiesFilename(properties_filename_.c_str(), "appcompat_override");
if (access(appcompat_filename_.c_str(), F_OK) != -1) {
  auto* appcompat_contexts = new (appcompat_override_contexts_data_) ContextsSerialized();
  appcompat_contexts->Initialize(true, appcompat_filename_.c_str(), fsetxattr_failed, load_default_path);
  appcompat_override_contexts_ = appcompat_contexts;
}
```

### Directory
- Path: `/dev/__properties__/appcompat_override` (property_service.cpp:81–82)
- Created by init if appcompat overrides exist

### Mirror Path in Update() (lines 305–315)
When updating a property, if `appcompat_override_contexts_` is set:

1. Find override_pi (same property name in override area) (line 295)
2. Copy old value to override dirty backup (line 306)
3. Set dirty bit on override_pi->serial (line 313)
4. Copy new value to override_pi->value (line 314)
5. Store new serial on override_pi->serial (line 322)

**Critical for seal**: Both the main property area AND the appcompat override area must be remapped MAP_PRIVATE to prevent the original file from seeing init's writes.

---

## 11. properties_serial — Global Notification Channel

**Location**: system_properties.cpp:325–333

```cpp
atomic_store_explicit(serial_pa->serial(),
                      atomic_load_explicit(serial_pa->serial(), memory_order_relaxed) + 1,
                      memory_order_release);
if (have_override) {
  atomic_store_explicit(override_serial_pa->serial(),
                        atomic_load_explicit(override_serial_pa->serial(), memory_order_relaxed) + 1,
                        memory_order_release);
}
__futex_wake(serial_pa->serial(), INT32_MAX);
```

**Critical for seal design**: 
- `serial_pa->serial()` points to the atomic counter at prop_area offset +4 (line 130–132, prop_area.h)
- This counter is read by **all processes** to detect system-wide property changes
- **DO NOT seal this with MAP_PRIVATE** — doing so breaks global notification
- Solution: seal only the **property data area** (data_ and onwards), leaving the serial counter on the shared mapping, or use a separate read-only shared serial area

---

## 12. Init EACCES Abort

**Location**: prop_area.cpp:63–68

```cpp
if (fd < 0) {
  if (errno == EACCES) {
    // "for consistency with the case where the process has already
    // mapped the page in and segfaults when trying to write to it"
    abort();
  }
  return nullptr;
}
```

**Consequence**: If seal changes file permissions and init tries to re-open the area (e.g., during reload), init will abort if EACCES. **Never modify file permissions on property area files during sealing.**

---

## 13. Tier A Implementation Checklist — ptrace MAP_PRIVATE Remap

```rust
// Pseudocode outline
fn seal_tier_a(init_pid: i32) -> Result<()> {
  // 1. Attach to init with ptrace(PTRACE_SEIZE)
  // 2. Stop init (PTRACE_INTERRUPT)
  // 3. Parse /proc/[init_pid]/maps to find property area mappings
  //    - Look for /dev/__properties__ (main area)
  //    - Look for /dev/__properties__/appcompat_override (if present)
  // 4. For each mapping [start, end]:
  //    a. Verify it matches PA_SIZE (128 KB) and magic/version on disk
  //    b. Open the underlying file (read-only, to avoid EACCES)
  //    c. Validate with map_fd_ro checks (uid=0, no group/world write)
  //    d. mmap(start, length, PROT_READ|PROT_WRITE, 
  //            MAP_PRIVATE|MAP_FIXED, fd, offset) into init's space
  //    e. Close fd
  // 5. Resume init (PTRACE_CONT)
  // 6. Return
}
```

**Key points**:
- Use PTRACE_PEEKTEXT/POKE or mmap(MAP_FIXED) on the traced process's /proc/[pid]/mem
- Ensure both property area and appcompat override area (if present) are remapped
- Do NOT remap the serial counter if using cross-process notification (or handle separately)

---

## 14. Tier B Implementation Checklist — __system_property_update Hook

```rust
// Pseudocode outline
fn seal_tier_b_install_hook(init_pid: i32) -> Result<()> {
  // 1. Attach to init with ptrace
  // 2. Stop init
  // 3. Locate __system_property_update symbol in init's libc.so
  //    - Use /proc/[pid]/maps to find libc.so base
  //    - Parse ELF to find __system_property_update offset
  // 4. Create inline trampoline hook:
  //    - Save original function prologue
  //    - Overwrite first bytes with jmp to hook function
  //    - Hook function intercepts (x0=pi, x1=value, w2=len) and:
  //      a. Logs or records property change
  //      b. Calls original __system_property_update via saved prologue
  //      c. Post-write: verify update reached private mapping (seal confirmed)
  // 5. Resume init
  // 6. Return
}
```

**Verification**: Hook receives calls only if init executes __system_property_update. If sealed correctly, the hook's writes to pi->value, pi->serial, etc. are private-copy only; original file remains unchanged.

---

## 15. Summary: Addresses Touched by Update()

| Address | Source | Offset in File | Type | Seal-Required |
|---------|--------|----------------|------|---------------|
| pi->serial | prop_info | +0 | atomic u32 | Yes |
| pi->value[0..91] | prop_info | +4 | char[92] | Yes |
| override_pi->serial | override prop_info | +0 | atomic u32 | Yes |
| override_pi->value[0..91] | override prop_info | +4 | char[92] | Yes |
| pa->dirty_backup_area() | prop_area data | +128 + sizeof(trie) | char[PROP_VALUE_MAX] | Yes |
| override_pa->dirty_backup_area() | override data | +128 + sizeof(trie) | char[PROP_VALUE_MAX] | Yes |
| serial_pa->serial() | prop_area header | +4 | atomic u32 | No (keep shared for global notification) |

**Seal strategy**: MAP_PRIVATE | MAP_FIXED remap covers all "Yes" entries. Keep serial_pa->serial() shared or handle via a separate read-only shared notification mechanism.

---

## References

- bionic/libc/system_properties/prop_info.h:44–89 (struct + static_assert)
- bionic/libc/system_properties/prop_info.cpp:38–55 (constructors)
- bionic/libc/system_properties/prop_area.h:92–178 (class definition)
- bionic/libc/system_properties/prop_area.cpp:49–50 (magic/version constants), 55–109 (map_prop_area_rw), 111–138 (map_fd_ro)
- bionic/libc/system_properties/system_properties.cpp:52–53 (serial macros), 270–336 (Update), 338–401 (Add), 162–174 (Find), 123–134 (appcompat init)
- bionic/libc/system_properties/system_properties.h:39–95 (class interface)
- bionic/libc/bionic/system_property_set.cpp:275–335 (__system_property_set), 418 (init call site)
- system/core/init/property_service.cpp:81–84 (appcompat folder), 177–191 (CheckMacPerms), 391–441 (PropertySet), 410–425 (update/add dispatch)
- system/core/init/property_service.h:33–43 (property_service interface)

