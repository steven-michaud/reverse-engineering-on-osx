// Template for an interpose library that can be used to hook C/C++ methods
// and/or swizzle Objective-C methods for debugging/reverse-engineering.
//
// A number of methods are provided to be called from your hooks that make use
// of Apple's Symbolication framework (which though undocumented is heavily
// used by Apple utilities such as crashreporterd and dtrace).  Particularly
// useful is PrintStackTrace().
//
// Once the interpose library is built, use it as follows:
//
// A) From a Terminal prompt:
//    1) export DYLD_INSERT_LIBRARIES=/full/path/to/interpose.dylib
//    2) /path/to/application
//
// B) From gdb:
//    1) set DYLD_INSERT_LIBRARIES /full/path/to/interpose.dylib
//    2) run

#include <dlfcn.h>
#include <pthread.h>
#include <libproc.h>
#include <stdarg.h>
#include <time.h>
#import <Cocoa/Cocoa.h>
#import <Carbon/Carbon.h>
#import <objc/Object.h>
extern "C" {
#include <mach-o/getsect.h>
}
#include <mach-o/dyld.h>
#include <mach-o/nlist.h>
#include <mach/vm_map.h>
#include <libgen.h>

class nsAutoreleasePool {
public:
    nsAutoreleasePool()
    {
        mLocalPool = [[NSAutoreleasePool alloc] init];
    }
    ~nsAutoreleasePool()
    {
        [mLocalPool release];
    }
private:
    NSAutoreleasePool *mLocalPool;
};

char *GetOwnerName(void *address);
char *GetAddressName(void *address);
void PrintAddress(void *address);
void PrintStackTrace(NSArray *addresses = nil);
BOOL SwizzleMethods(Class aClass, SEL orgMethod, SEL posedMethod, BOOL classMethods);

char gProcPath[PROC_PIDPATHINFO_MAXSIZE] = {0};

static void MaybeGetProcPath()
{
  if (gProcPath[0]) {
    return;
  }
  proc_pidpath(getpid(), gProcPath, sizeof(gProcPath) - 1);
}

static void LogWithFormatV(bool decorate, CFStringRef format, va_list args)
{
  MaybeGetProcPath();

  CFStringRef message = CFStringCreateWithFormatAndArguments(kCFAllocatorDefault, NULL,
                                                             format, args);

  int msgLength = CFStringGetMaximumSizeForEncoding(CFStringGetLength(message),
                                                    kCFStringEncodingUTF8);
  char *msgUTF8 = (char *) calloc(msgLength + 1, 1);
  CFStringGetCString(message, msgUTF8, msgLength, kCFStringEncodingUTF8);
  CFRelease(message);

  char *finished = (char *) calloc(msgLength + 1024, 1);
  const time_t currentTime = time(NULL);
  char timestamp[30] = {0};
  ctime_r(&currentTime, timestamp);
  timestamp[strlen(timestamp) - 1] = 0;
  if (decorate) {
    sprintf(finished, "(%s) %s[%u] %s\n",
            timestamp, gProcPath, getpid(), msgUTF8);
  } else {
    sprintf(finished, "%s\n", msgUTF8);
  }
  free(msgUTF8);

  fputs(finished, stdout);

  free(finished);
}

static void LogWithFormat(bool decorate, const char *format, ...)
{
  va_list args;
  va_start(args, format);
  CFStringRef formatCFSTR = CFStringCreateWithCString(kCFAllocatorDefault, format,
                                                      kCFStringEncodingUTF8);
  LogWithFormatV(decorate, formatCFSTR, args);
  CFRelease(formatCFSTR);
  va_end(args);
}

extern "C" void interposelib_LogWithFormatV(bool decorate, const char *format, va_list args)
{
  CFStringRef formatCFSTR = CFStringCreateWithCString(kCFAllocatorDefault, format,
                                                      kCFStringEncodingUTF8);
  LogWithFormatV(decorate, formatCFSTR, args);
  CFRelease(formatCFSTR);
}

extern "C" void interposelib_PrintStackTrace()
{
  PrintStackTrace();
}

// Helper method for module_dysym() below.
static
void GetModuleHeaderSlideAndOffset(const char *moduleName,
#ifdef __LP64__
                                   const struct mach_header_64** pMh,
#else
                                   const struct mach_header** pMh,
#endif
                                   intptr_t *pVmaddrSlide,
                                   uint32_t *pOffset)
{
  bool moduleNameIsBasename =
    (strcmp(basename((char *)moduleName), moduleName) == 0);
  if (pMh) {
    *pMh = NULL;
  }
  if (pVmaddrSlide) {
    *pVmaddrSlide = 0;
  }
  if (pOffset) {
    *pOffset = 0;
  }
  for (uint32_t i = 0; i < _dyld_image_count(); ++i) {
    const char *name = _dyld_get_image_name(i);
    bool match = false;
    if (moduleNameIsBasename) {
      match = (strstr(basename((char *)name), moduleName) != NULL);
    } else {
      match = (strstr(name, moduleName) != NULL);
    }
    if (match) {
      if (pMh) {
        *pMh =
#ifdef __LP64__
        (const struct mach_header_64 *)
#endif
        _dyld_get_image_header(i);
      }
      if (pVmaddrSlide) {
        *pVmaddrSlide = _dyld_get_image_vmaddr_slide(i);
      }
      if (pOffset) {
        *pOffset = i;
      }
      break;
    }
  }
}

// Helper method for module_dysym() below.
static const
#ifdef __LP64__
struct segment_command_64 *
GetSegment(const struct mach_header_64* mh,
#else
struct segment_command *
GetSegment(const struct mach_header* mh,
#endif
           const char *segname,
           uint32_t *numFollowingCommands)
{
  if (numFollowingCommands) {
    *numFollowingCommands = 0;
  }
  uint32_t numCommands = mh->ncmds;

#ifdef __LP64__
  const struct segment_command_64 *aCommand = (struct segment_command_64 *)
    ((uintptr_t)mh + sizeof(struct mach_header_64));
#else
  const struct segment_command *aCommand = (struct segment_command *)
    ((uintptr_t)mh + sizeof(struct mach_header));
#endif

  for (uint32_t i = 1; i <= numCommands; ++i) {
#ifdef __LP64__
    if (aCommand->cmd != LC_SEGMENT_64)
#else
    if (aCommand->cmd != LC_SEGMENT)
#endif
    {
      break;
    }
    if (strcmp(segname, aCommand->segname) == 0) {
      if (numFollowingCommands) {
        *numFollowingCommands = numCommands-i;
      }
      return aCommand;
    }
    aCommand =
#ifdef __LP64__
      (struct segment_command_64 *)
#else
      (struct segment_command *)
#endif
      ((uintptr_t)aCommand + aCommand->cmdsize);
  }

  return NULL;
}

// A variant of dlsym() that can find non-exported (non-public) symbols.
// Unlike with dlsym() and friends, 'symbol' should be specified exactly as it
// appears in the symbol table (and the output of programs like 'nm').  In
// other words, 'symbol' should (most of the time) be prefixed by an "extra"
// underscore.  The reason is that some symbols (especially non-public ones)
// don't have any underscore prefix, even in the symbol table.
extern "C" void *module_dlsym(const char *module_name, const char *symbol)
{
#ifdef __LP64__
  const struct mach_header_64 *mh = NULL;
#else
  const struct mach_header *mh = NULL;
#endif
  intptr_t vmaddr_slide = 0;
  uint32_t module_offset = 0;
  GetModuleHeaderSlideAndOffset(module_name, &mh,
                                &vmaddr_slide, &module_offset);
  if (!mh) {
    return NULL;
  }

  uint32_t numFollowingCommands = 0;
#ifdef __LP64__
  const struct segment_command_64 *linkeditSegment =
#else
  const struct segment_command *linkeditSegment =
#endif
    GetSegment(mh, "__LINKEDIT", &numFollowingCommands);
  if (!linkeditSegment) {
    return NULL;
  }
  uintptr_t fileoffIncrement =
    linkeditSegment->vmaddr - linkeditSegment->fileoff;

  struct symtab_command *symtab = (struct symtab_command *)
    ((uintptr_t)linkeditSegment + linkeditSegment->cmdsize);
  for (uint32_t i = 1;; ++i) {
    if (symtab->cmd == LC_SYMTAB) {
      break;
    }
    if (i == numFollowingCommands) {
      return NULL;
    }
    symtab = (struct symtab_command *)
      ((uintptr_t)symtab + symtab->cmdsize);
  }
  uintptr_t symbolTableOffset =
    symtab->symoff + fileoffIncrement + vmaddr_slide;
  uintptr_t stringTableOffset =
    symtab->stroff + fileoffIncrement + vmaddr_slide;

  struct dysymtab_command *dysymtab = (struct dysymtab_command *)
    ((uintptr_t)symtab + symtab->cmdsize);
  if (dysymtab->cmd != LC_DYSYMTAB) {
    return NULL;
  }

  void *retval = NULL;
  for (int i = 1; i <= 2; ++i) {
    uint32_t index;
    uint32_t count;
    if (i == 1) {
      index = dysymtab->ilocalsym;
      count = index + dysymtab->nlocalsym;
    } else {
      index = dysymtab->iextdefsym;
      count = index + dysymtab->nextdefsym;
    }

    for (uint32_t j = index; j < count; ++j) {
#ifdef __LP64__
      struct nlist_64 *symbolTableItem = (struct nlist_64 *)
        (symbolTableOffset + j * sizeof(struct nlist_64));
#else
      struct nlist *symbolTableItem = (struct nlist *)
        (symbolTableOffset + j * sizeof(struct nlist));
#endif
      uint8_t type = symbolTableItem->n_type;
      if ((type & N_STAB) || ((type & N_TYPE) != N_SECT)) {
        continue;
      }
      uint8_t sect = symbolTableItem->n_sect;
      if (!sect) {
        continue;
      }
      const char *stringTableItem = (char *)
        (stringTableOffset + symbolTableItem->n_un.n_strx);
      if (strcmp(symbol, stringTableItem)) {
        continue;
      }
      retval = (void *) (symbolTableItem->n_value + vmaddr_slide);
      break;
    }
  }

  return retval;
}

typedef struct _nsRawFunctionInfo {
  void *hookAddress;
  void *origAddress;
  uint32_t topBytes;  // Offset to the beginning of a machine instruction
  void *superAddress; // Address to call the original function from the hook
} nsRawFunctionInfo;

#ifdef __x86_64__
  #define JUMP_BYTES 12
#endif
#ifdef __i386__
  #define JUMP_BYTES 5
#endif

#define FUNC_ALIGN 16

// A method that hooks "raw" function pointers using binary patching.  A more
// common technique (such as that normally used by an interpose library via
// the INTERPOSE_FUNCTION() macro below) is to patch the jump tables or stub
// tables used to "import" functions from external dylibs.  But that only
// works for calls from one module to another.  This method can hook calls to
// a function from *anywhere* -- the same module or another one.  It can also
// hook calls to non-exported methods (which by definition can only be called
// from within the same module).
//
// The basic strategy is as follows:
//   1) Copy the first N bytes of the original function to a buffer allocated
//      using a low-level method like vm_allocate().  N must be at least as
//      large as the machine code for the jmp instruction in step 2, and must
//      specify an offset to the beginning of a machine-code instruction.
//   2) Copy a machine-code jmp instruction to the beginning of the original
//      function, making the hook function its target.
//   3) Copy a machine-code jmp instruction to offset N in the buffer from
//      step 1, making its target the instruction at offset N in the original
//      function.
//
// The buffer from step 1 can be cast appropriately and called as if it was
// the original function.  So it can be called from the hook -- though this
// isn't required.
//
// One generally will need to use another low-level function like vm_protect()
// to make it possible to write to the original function (and to restore the
// original permissions afterwards).  One also needs to ensure that the buffer
// allocated in step 1 has the appropriate permissions (including execute
// permission).
//
// Since the original function and the step 1 buffer might be very far apart
// in virtual memory, we need to use a jmp instruction that can encompass the
// entire address space.  In 32-bit mode we can use a 32-bit jmp immediate
// instruction:
//
// __asm__("jmpl $0x12345678");
//
// But there's no corresponding jmp instruction for 64-bit mode, so instead we
// use the following:
//
// __asm__("movq $0x1234567812345678,%rax");
// __asm__("jmpq *%rax");
//
// The rax register is never used to pass parameters to a function, so it
// should (generally) be safe to use it.  Here are the machine-code equivalents
// of the previous two kinds of jmp instruction:
//
// E978563412
// 48B87856341278563412FFE0
//
// One must look at the machine code of the original function (using a
// disassembler like Hopper Disassembler http://www.hopperapp.com/) to find
// whether it's safe to use HookRawFunctions() on it, and of course to find
// the correct value for N in the three steps above (i.e. for 'topBytes').
// A function won't be safe to hook if it
//
// 1) Is too short, or
// 2) In 64-bit mode, makes use of the rax register in the top N bytes, or
// 3) Contains any near or short calls or jmps in the top N bytes
//
// A near or short call or jmp only works correctly (finds its correct
// target) if it's called from its original location.  But the buffer
// allocated in step 1 above is *not* at the function's original location.
//
// HookRawFunctions() isn't thread-safe.  So it musn't be called when any of
// the functions to be hooked might be in use.  The best approach is probably
// to call it as the module containing the functions to be hooked is being
// loaded/initialized.
static void HookRawFunctions(nsRawFunctionInfo *functions, uint32_t numFunctions)
{
  uint32_t superBytesTotal = 0;
  for (uint32_t i = 0; i < numFunctions; ++i) {
    superBytesTotal += (functions[i].topBytes + JUMP_BYTES);
    uint32_t align_miss = (superBytesTotal % FUNC_ALIGN);
    if (align_miss) {
      superBytesTotal += (FUNC_ALIGN - align_miss);
    }
    functions[i].superAddress = NULL;
  }
  uint32_t numPages = (superBytesTotal / 4096) + 1;

  vm_address_t blockAddress = 0;
  if (vm_allocate(mach_task_self(), &blockAddress, numPages * 4096, true) != KERN_SUCCESS) {
    return;
  }

  intptr_t superAddress = blockAddress;
  for (uint32_t i = 0; i < numFunctions; ++i) {
    intptr_t topBytes = functions[i].topBytes;
    intptr_t hookAddress = (intptr_t) functions[i].hookAddress;
    intptr_t origAddress = (intptr_t) functions[i].origAddress;

    memcpy((void *)superAddress, (void *)origAddress, topBytes);

    unsigned char *opcodeAddr =
      (unsigned char *) (superAddress + topBytes);
    intptr_t displacement = 0;
#ifdef __i386__
    intptr_t ip = superAddress + topBytes + JUMP_BYTES;
    displacement = origAddress + topBytes - ip;
    int32_t *displacementAddr = (int32_t *) (opcodeAddr + 1);
    displacementAddr[0] = (int32_t) displacement;
    opcodeAddr[0] = 0xE9;
#endif
#ifdef __x86_64__
    displacement = origAddress + topBytes;
    int64_t *displacementAddr = (int64_t *) (opcodeAddr + 2);
    displacementAddr[0] = (int64_t) displacement;
    opcodeAddr[0] = 0x48;
    opcodeAddr[1] = 0xB8;
    opcodeAddr[10] = 0xFF;
    opcodeAddr[11] = 0xE0;
#endif

    vm_protect(mach_task_self(), origAddress, topBytes, NO,
               VM_PROT_READ | VM_PROT_EXECUTE | VM_PROT_WRITE);

    opcodeAddr = (unsigned char *) origAddress;
#ifdef __i386__
    ip = origAddress + topBytes;
    displacement = hookAddress - ip;
    displacementAddr = (int32_t *) (opcodeAddr + 1);
    displacementAddr[0] = (int32_t) displacement;
    opcodeAddr[0] = 0xE9;
#endif
#ifdef __x86_64__
    displacement = hookAddress;
    displacementAddr = (int64_t *) (opcodeAddr + 2);
    displacementAddr[0] = (int64_t) displacement;
    opcodeAddr[0] = 0x48;
    opcodeAddr[1] = 0xB8;
    opcodeAddr[10] = 0xFF;
    opcodeAddr[11] = 0xE0;
#endif

    vm_protect(mach_task_self(), origAddress, topBytes, NO,
               VM_PROT_READ | VM_PROT_EXECUTE);

    functions[i].superAddress = (void *) superAddress;
    superAddress += (topBytes + JUMP_BYTES);
    uint32_t align_miss = (superAddress % FUNC_ALIGN);
    if (align_miss) {
      superAddress += (FUNC_ALIGN - align_miss);
    }
  }

  vm_protect(mach_task_self(), blockAddress, numPages * 4096, NO,
             VM_PROT_READ | VM_PROT_EXECUTE);
}

const char *GetImageName(const struct mach_header* mh)
{
  const char *retval = NULL;
  for (uint32_t i = 0; i < _dyld_image_count(); ++i) {
    const struct mach_header *aMh = _dyld_get_image_header(i);
    if (aMh == mh) {
      retval = _dyld_get_image_name(i);
      break;
    }
  }
  return retval;
}

void OnAddImage(const struct mach_header* mh, intptr_t vmaddr_slide)
{
  // Call HookRawFunctions() here:
  //const char *image_name = GetImageName(mh);
  //if (strcmp(basename((char *)image_name), "module_name") == 0) {
  //  ...
  //}
}

class loadHandler
{
public:
  loadHandler();
  ~loadHandler() {}
};

loadHandler::loadHandler()
{
  // We need to call this as early as possible, to ensure either that
  // HookRawFunctions() is called as its target module is being loaded,
  // or as *this* module is being loaded.  HookRawFunctions() isn't
  // thread-safe, so it must not be called while any of the functions
  // it hooks might be running.
  _dyld_register_func_for_add_image(OnAddImage);
}

loadHandler handler = loadHandler();

Class gSymbolicatorClass = nil;
static BOOL gSymbolicationLoaded = NO;
static BOOL loadSymbolication()
{
  if (gSymbolicationLoaded) {
    return YES;
  }
  // Needed for printing stack traces.  Available on OS X 10.5 and up.
  if (dlopen("/System/Library/PrivateFrameworks/Symbolication.framework/Symbolication", RTLD_LAZY)) {
    gSymbolicationLoaded = YES;
    Class VMUDebugMapExtractorClass = ::NSClassFromString(@"VMUDebugMapExtractor");
    SwizzleMethods(VMUDebugMapExtractorClass, @selector(debugMapExtractorWithMachOHeader:),
                   @selector(VMUDebugMapExtractor_debugMapExtractorWithMachOHeader:), YES);
    gSymbolicatorClass = ::NSClassFromString(@"VMUSymbolicator");

    // Swizzle other methods here
  }

  return gSymbolicationLoaded;
}

pthread_t gMainThreadID = 0;

bool IsMainThread()
{
  return (gMainThreadID == pthread_self());
}

static int Hooked_pthread_once(pthread_once_t *once_control, void (*init_routine)(void))
{
  int retval = pthread_once(once_control, init_routine);
  if (!gMainThreadID) {
    gMainThreadID = pthread_self();
  }
  return retval;
}

extern "C" void *NSPushAutoreleasePool();

static void *Hooked_NSPushAutoreleasePool()
{
  void *retval = NSPushAutoreleasePool();
  if (IsMainThread()) {
    loadSymbolication();
  }
  return retval;
}

// Put other hooked methods and swizzled classes here

#pragma mark -

struct interpose_substitution {
  const void* replacement;
  const void* original;
};

#define INTERPOSE_FUNCTION(function) \
    { reinterpret_cast<const void*>(Hooked_##function), \
      reinterpret_cast<const void*>(function) }

__attribute__((used)) static const interpose_substitution substitutions[]
    __attribute__((section("__DATA, __interpose"))) = {
  INTERPOSE_FUNCTION(pthread_once),
  INTERPOSE_FUNCTION(NSPushAutoreleasePool),
};

// What follows are definitions of the Symbolication interfaces we use to get
// stack traces.  The Symbolication framework is an undocumented, private
// framework available on OS X 10.5 and up.  It's used by Apple utilities
// such as dtrace.  http://www.cocoadev.com/index.pl?StackTraces has basic
// information on how to use the Symbolication framework.

@interface VMUAddressRange : NSObject <NSCoding>
{
}

@end

@interface VMUSymbol : VMUAddressRange <NSCopying>
{
}

- (NSString *)name;
- (NSString *)description;
- (id)text;

@end

@interface VMUSymbolOwner : NSObject <NSCopying>
{
}

- (NSString *)name;

@end

// We must override the debugMapExtractorWithMachOHeader method:  Otherwise
// the Symbolication framework can take a minute or more to initialize!!
// We don't need the information in the "debug maps" (Dwarf or dsym debugging
// information) to get simple stack traces.
@interface NSObject (VMUDebugMapExtractorMethodSwizzling)
+ (id)VMUDebugMapExtractor_debugMapExtractorWithMachOHeader:(id)machHeader;
@end

@implementation NSObject (VMUDebugMapExtractorMethodSwizzling)

+ (id)VMUDebugMapExtractor_debugMapExtractorWithMachOHeader:(id)machHeader
{
  return nil;
}

@end

@interface VMUSymbolicator : NSObject
{
}

+ (VMUSymbolicator *)symbolicatorForPid:(int)pid;
- (VMUSymbol *)symbolForAddress:(unsigned long long)address;
- (VMUSymbolOwner *)symbolOwnerForAddress:(unsigned long long)address;

@end

@interface VMUSymbolicator (PerformanceOptimization)
- (id)symbolOwnerNameForAddress:(unsigned long long)fp8;
@end

char *GetOwnerName(void *address)
{
  static char holder[1024] = {0};
  if (!loadSymbolication()) {
    holder[0] = 0;
    return holder;
  }
  VMUSymbolicator *symbolicator = [gSymbolicatorClass symbolicatorForPid:getpid()];
  if (!symbolicator) {
    holder[0] = 0;
    return holder;
  }

  VMUSymbol *symbol =
    [symbolicator symbolForAddress:(unsigned long long)address];
  NSString *ownerName = nil;
  if ([symbolicator respondsToSelector:@selector(symbolOwnerNameForAddress:)]) {
    ownerName =
      [symbolicator symbolOwnerNameForAddress:(unsigned long long)address];
  } else {
    VMUSymbolOwner *owner =
      [symbolicator symbolOwnerForAddress:(unsigned long long)address];
    ownerName = [owner name];
  }
  if (ownerName) {
    strcpy(holder, [ownerName UTF8String]);
    return holder;
  }
  holder[0] = 0;
  return holder;
}

char *GetAddressName(void *address)
{
  static char holder[1024] = {0};
  if (!loadSymbolication()) {
    holder[0] = 0;
    return holder;
  }
  VMUSymbolicator *symbolicator = [gSymbolicatorClass symbolicatorForPid:getpid()];
  if (!symbolicator) {
    holder[0] = 0;
    return holder;
  }

  VMUSymbol *symbol =
    [symbolicator symbolForAddress:(unsigned long long)address];
  if (symbol && [symbol name]) {
    strcpy(holder, [[symbol name] UTF8String]);
    return holder;
  }
  holder[0] = 0;
  return holder;
}

void PrintAddress(void *address)
{
  if (!loadSymbolication()) {
    return;
  }
  VMUSymbolicator *symbolicator = [gSymbolicatorClass symbolicatorForPid:getpid()];
  if (!symbolicator) {
    return;
  }

  VMUSymbol *symbol =
    [symbolicator symbolForAddress:(unsigned long long)address];
  NSString *ownerName = nil;
  if ([symbolicator respondsToSelector:@selector(symbolOwnerNameForAddress:)]) {
    ownerName =
      [symbolicator symbolOwnerNameForAddress:(unsigned long long)address];
  } else {
    VMUSymbolOwner *owner =
      [symbolicator symbolOwnerForAddress:(unsigned long long)address];
    ownerName = [owner name];
  }
  LogWithFormat(false, "    (%@) %@, %p", ownerName, [symbol name], address);
}

void PrintStackTrace(NSArray *addresses)
{
  if (!loadSymbolication()) {
    return;
  }
  VMUSymbolicator *symbolicator = [gSymbolicatorClass symbolicatorForPid:getpid()];
  if (!symbolicator) {
    return;
  }

  if (!addresses) {
    addresses = [NSThread callStackReturnAddresses];
  }
  NSUInteger count = [addresses count];
  for (NSUInteger i = 0; i < count; ++i) {
    NSNumber *item = (NSNumber *) [addresses objectAtIndex:i];
    VMUSymbol *symbol =
      [symbolicator symbolForAddress:[item unsignedLongLongValue]];
    NSString *ownerName = nil;
    if ([symbolicator respondsToSelector:@selector(symbolOwnerNameForAddress:)]) {
      ownerName =
        [symbolicator symbolOwnerNameForAddress:[item unsignedLongLongValue]];
    } else {
      VMUSymbolOwner *owner =
        [symbolicator symbolOwnerForAddress:[item unsignedLongLongValue]];
      ownerName = [owner name];
    }
    LogWithFormat(false, "    (%@) %@, %p",
                  ownerName, [symbol name], (void *)[item unsignedLongLongValue]);
  }
}

BOOL SwizzleMethods(Class aClass, SEL orgMethod, SEL posedMethod, BOOL classMethods)
{
  Method original = nil;
  Method posed = nil;

  if (classMethods) {
    original = class_getClassMethod(aClass, orgMethod);
    posed = class_getClassMethod(aClass, posedMethod);
  } else {
    original = class_getInstanceMethod(aClass, orgMethod);
    posed = class_getInstanceMethod(aClass, posedMethod);
  }

  if (!original || !posed)
    return NO;

  method_exchangeImplementations(original, posed);

  return YES;
}
