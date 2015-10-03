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
#include <execinfo.h>
#import <Cocoa/Cocoa.h>
#import <Carbon/Carbon.h>
#import <OpenGL/OpenGL.h>
#import <objc/Object.h>

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

class ReconfigurationCallbackInfo {
public:
    ReconfigurationCallbackInfo(CGDisplayReconfigurationCallBack aCallback,
                                void *aUserInfo, char *aOwnerName)
    {
      mCallbackProc = aCallback;
      mUserInfo = aUserInfo;
      size_t ownerNameLength = strlen(aOwnerName);
      mOwnerName = (char *) calloc(ownerNameLength + 2, 1);
      if (mOwnerName) {
        strcpy(mOwnerName, aOwnerName);
      }
    }
    ~ReconfigurationCallbackInfo()
    {
      free(mOwnerName);
    }
    CGDisplayReconfigurationCallBack getCallback() { return mCallbackProc; }
    void *getUserInfo() { return mUserInfo; }
    char *getOwnerName() { return mOwnerName; }
private:
    CGDisplayReconfigurationCallBack mCallbackProc;
    void *mUserInfo;
    char *mOwnerName;
};

Boolean CallbackInfoEqualCallback(const void *value1,
                                  const void *value2)
{
  ReconfigurationCallbackInfo *info1 = (ReconfigurationCallbackInfo *) value1;
  ReconfigurationCallbackInfo *info2 = (ReconfigurationCallbackInfo *) value2;
  return ((info1->getUserInfo() == info2->getUserInfo()) &&
          (info1->getCallback() == info2->getCallback()));
}

CFHashCode CallbackInfoHashCallback(const void *value)
{
  ReconfigurationCallbackInfo *info = (ReconfigurationCallbackInfo *) value;
  CFHashCode retval = (((CFHashCode)info->getUserInfo()) << 1);
  retval += (CFHashCode) info->getCallback();
  return retval;
}

CFMutableSetRef gCallbackInfo = NULL;

static bool CheckCallbackInfo()
{
  if (gCallbackInfo) {
    return true;
  }
  CFSetCallBacks callbacks = {0};
  callbacks.equal = CallbackInfoEqualCallback;
  callbacks.hash = CallbackInfoHashCallback;
  gCallbackInfo = CFSetCreateMutable(kCFAllocatorDefault, 0, &callbacks);
  return (gCallbackInfo != NULL);
}

static void ReconfigurationCallback(CGDirectDisplayID display,
                                    CGDisplayChangeSummaryFlags flags,
                                    void *userInfo)
{
  ReconfigurationCallbackInfo *info = (ReconfigurationCallbackInfo *) userInfo;
  CGDisplayReconfigurationCallBack orgCallback = info->getCallback();
  void *orgUserInfo = info->getUserInfo();
  char *orgOwnerName = info->getOwnerName();
  nsAutoreleasePool localPool;
  NSLog(@"ReconfigurationCallback(): display %p, flags %p, userInfo %p, ownerName %s, calling ...",
        (void *) display, (void *) flags, orgUserInfo, orgOwnerName);
  PrintAddress((void *)orgCallback);
  orgCallback(display, flags, orgUserInfo);
}

static CGError Hooked_CGDisplayRegisterReconfigurationCallback(CGDisplayReconfigurationCallBack proc,
                                                               void *userInfo)
{
  char *ownerName = NULL;
  void **addresses = (void **) calloc(2, sizeof(void *));
  if (addresses) {
    int count = backtrace(addresses, 2);
    if (count == 2) {
      ownerName = GetOwnerName(addresses[1]);
    }
    free(addresses);
  }
  ReconfigurationCallbackInfo *info = new ReconfigurationCallbackInfo(proc, userInfo, ownerName);
  bool succeeded = CheckCallbackInfo();
  if (succeeded) {
    succeeded = !CFSetContainsValue(gCallbackInfo, info);
  }
  CGError retval;
  if (succeeded) {
    CFSetAddValue(gCallbackInfo, info);
    retval = CGDisplayRegisterReconfigurationCallback(ReconfigurationCallback, info);
  } else {
    delete info;
    retval = CGDisplayRegisterReconfigurationCallback(proc, userInfo);
  }
  nsAutoreleasePool localPool;
  NSLog(@"CGDisplayRegisterReconfigurationCallback(): proc %p, userInfo %p, returning %i, ownerName %s",
        proc, userInfo, retval, ownerName);
  PrintStackTrace();
  return retval;
}

static CGError Hooked_CGDisplayRemoveReconfigurationCallback(CGDisplayReconfigurationCallBack proc,
                                                             void *userInfo)
{
  CGError retval;
  ReconfigurationCallbackInfo info(proc, userInfo, (char *) "");
  bool succeeded = CheckCallbackInfo();
  if (succeeded) {
    succeeded = CFSetContainsValue(gCallbackInfo, &info);
  }
  if (succeeded) {
    ReconfigurationCallbackInfo *orgInfo =
      (ReconfigurationCallbackInfo *) CFSetGetValue(gCallbackInfo, &info);
    retval = CGDisplayRemoveReconfigurationCallback(ReconfigurationCallback,
                                                    orgInfo);
    CFSetRemoveValue(gCallbackInfo, orgInfo);
    delete orgInfo;
  } else {
    retval = CGDisplayRemoveReconfigurationCallback(proc, userInfo);
  }
  nsAutoreleasePool localPool;
  NSLog(@"CGDisplayRemoveReconfigurationCallback(): proc %p, userInfo %p, returning %i",
        proc, userInfo, retval);
  PrintStackTrace();
  return retval;
}

extern "C" CGLError CGLUpdateContext(CGLContextObj ctx);

static CGLError Hooked_CGLUpdateContext(CGLContextObj ctx)
{
  CGLError retval = CGLUpdateContext(ctx);
  nsAutoreleasePool localPool;
  bool log = true;
  char *ownerName = nil;
  void **addresses = (void **) calloc(2, sizeof(void *));
  if (addresses) {
    int count = backtrace(addresses, 2);
    if (count == 2) {
      ownerName = GetOwnerName(addresses[1]);
    }
    free(addresses);
  }
  if (ownerName && !strcmp(ownerName, "AppKit")) {
    log = false;
  }
  if (log) {
    NSLog(@"CGLUpdateContext(): ctx %p, retain count %u, returning %i",
          ctx, CGLGetContextRetainCount(ctx), retval);
    PrintStackTrace();
  }
  return retval;
}

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
  INTERPOSE_FUNCTION(CGDisplayRegisterReconfigurationCallback),
  INTERPOSE_FUNCTION(CGDisplayRemoveReconfigurationCallback),
  INTERPOSE_FUNCTION(CGLUpdateContext),
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
  NSLog(@"    (%@) %@, %p", ownerName, [symbol name], address);
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
    NSLog(@"    (%@) %@, %p",
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
