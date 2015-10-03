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
#include <libgen.h>
#import <Cocoa/Cocoa.h>
#import <Carbon/Carbon.h>
#import <OpenGL/OpenGL.h>
#import <OpenGL/CGLRenderers.h>
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

static const char *RendererIDString(GLint ID)
{
  static char holder[256] = {0};
  switch (ID) {
    case kCGLRendererGenericID: return "kCGLRendererGenericID";
    case kCGLRendererGenericFloatID: return "kCGLRendererGenericFloatID";
    case kCGLRendererAppleSWID: return "kCGLRendererAppleSWID";
    case kCGLRendererATIRage128ID: return "kCGLRendererATIRage128ID";
    case kCGLRendererATIRadeonID: return "kCGLRendererATIRadeonID";
    case kCGLRendererATIRageProID: return "kCGLRendererATIRageProID";
    case kCGLRendererATIRadeon8500ID: return "kCGLRendererATIRadeon8500ID";
    case kCGLRendererATIRadeon9700ID: return "kCGLRendererATIRadeon9700ID";
    case kCGLRendererATIRadeonX1000ID: return "kCGLRendererATIRadeonX1000ID";
    case kCGLRendererATIRadeonX2000ID: return "kCGLRendererATIRadeonX2000ID";
    case kCGLRendererATIRadeonX3000ID: return "kCGLRendererATIRadeonX3000ID";
    case kCGLRendererGeForce2MXID: return "kCGLRendererGeForce2MXID";
    case kCGLRendererGeForce3ID: return "kCGLRendererGeForce3ID";
    case kCGLRendererGeForceFXID: return "kCGLRendererGeForceFXID";
    case kCGLRendererGeForce8xxxID: return "kCGLRendererGeForce8xxxID";
    case kCGLRendererVTBladeXP2ID: return "kCGLRendererVTBladeXP2ID";
    case kCGLRendererIntel900ID: return "kCGLRendererIntel900ID";
    case kCGLRendererIntelX3100ID: return "kCGLRendererIntelX3100ID";
    case kCGLRendererIntelHDID: return "kCGLRendererIntelHDID";
    case kCGLRendererMesa3DFXID: return "kCGLRendererMesa3DFXID";
    default: {
      sprintf(holder, "Unknown(%p)", (void *) ID);
      return (const char *) holder;
    }
  }
}

static CGLError Hooked_CGLDescribeRenderer(CGLRendererInfoObj rend,
                                           GLint rend_num,
                                           CGLRendererProperty prop,
                                           GLint *value)
{
  CGLError retval = CGLDescribeRenderer(rend, rend_num, prop, value);
  nsAutoreleasePool localPool;
  if (prop == kCGLRPRendererID) {
    GLint orgValue = *value;
    if ((orgValue & kCGLRendererIDMatchingMask) > kCGLRendererGenericFloatID) {
      *value = kCGLRendererIntelX3100ID;
    }
    NSLog(@"CGLDescribeRenderer(), prop kCGLRPRendererID, orgValue %s, value %s",
          RendererIDString(orgValue & kCGLRendererIDMatchingMask),
          RendererIDString(*value & kCGLRendererIDMatchingMask));
    PrintStackTrace();
  }
  return retval;
}

// When Flash hardware acceleration is on, this is only called from Flash code
// in CoreGraphics drawing mode
static void Hooked_CGContextDrawImage(CGContextRef c, CGRect rect, CGImageRef image)
{
  CGContextDrawImage(c, rect, image);
  bool log = false;
  void **addresses = (void **) calloc(2, sizeof(void *));
  if (addresses) {
    int count = backtrace(addresses, 2);
    if (count == 2) {
      Dl_info addressInfo = {0};
      ::dladdr(addresses[1], &addressInfo);
      char *ownerName = basename((char *)addressInfo.dli_fname);
      if (ownerName && !strcmp(ownerName, "FlashPlayer-10.6")) {
        log = true;
      }
    }
    free(addresses);
  }
  if (log) {
    NSLog(@"CGContextDrawImage() called from Flash");
    PrintStackTrace();
  }
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
  INTERPOSE_FUNCTION(CGLDescribeRenderer),
  INTERPOSE_FUNCTION(CGContextDrawImage),
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
