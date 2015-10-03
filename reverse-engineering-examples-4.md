# Example 4: Locating the Source of a Problem Using a Crash Stack

This example comes from [crash in glcGetIOAccelService in Flash
plugin-container
process](https://bugzilla.mozilla.org/show_bug.cgi?id=816976), which
concerned a crash deep in system code that only happened with the
Flash plugin, and only on OS X 10.8.X.  Because it was associated with
Flash, it might be a Flash bug.  But the crash stacks didn't
(apparently) have any Flash code in them.  And the fact that the
crashes only happened on OS X 10.8.X suggested they might be an OS
bug.

* [`Makefile`](examples4/Makefile)
* [`interpose.mm`](examples4/interpose.mm)

The top part of the crash stacks was as follows:

        0   OpenGL        glcGetIOAccelService    
        1   OpenGL        CGLUpdateContext      
        2   CoreGraphics  CGSReconfigNotifierCalloutListInvokeAll
        3   CoreGraphics  displayConfigFinalizedProc 
        4   CoreGraphics  displayAcceleratorChangedProc 
        5   CoreGraphics  CGSPostLocalNotification 
        6   CoreGraphics  notify_datagram_handler 
        7   CoreGraphics  CGSDispatchDatagramsFromStream 
        8   CoreGraphics  snarf_events 
        9   CoreGraphics  CGSGetNextEventRecordInternal 
        10  CoreGraphics  CGEventCreateNextEvent 
        11  HIToolbox     PullEventsFromWindowServerOnConnection
        ...

At first I concentrated on the top of this stack --
`glcGetIOAccelService`, the so-called "signature".  That's usually a
good idea, but in this case it turned out to be a complete waste of
time.  In fact what was being called was not `glcGetIOAccelService` at
all, but a non-exported method at offset `0x32F4` in the OpenGL
framework (in 64-bit mode), which happens to located near
`glcGetIOAccelService`.

For any entry in a Socorro crash stack, you can find the offset (from
the beginning of a method) where execution was taking place (at the
time of the crash) in its "raw dump".  Here's the part relevant to the
entry for `glcGetIOAccelService`.  The offset is `0xACB`.

        0|0|OpenGL|glcGetIOAccelService|||0xacb

The `glcGetIOAccelService` method is quite short -- only about `0x90`
bytes.  So offset `0xACB` from the beginning of `glcGetIOAccelService`
is inside another method altogether.

Once I realized I was wasting my time with `glcGetIOAccelService`, I
started to pay more attention to the rest of the crash stack.  I made
a lucky guess that `displayAcceleratorChangedProc` had to do with
"graphics switching" in Apple laptops.  To test this hypothesis I ran
Firefox in `gdb` and set a breakpoint on
`displayAcceleratorChangedProc`.  Then I used the very useful
[gfxCardStatus utility](http://gfx.io/) to force a switch from one
kind of graphics hardware to the other.  This caused `gdb` to break on
`displayAcceleratorChangedProc`.

`displayAcceleratorChangedProc` is implemented in the CoreGraphics
framework, and that's where all the action seemed to be happening.  If
you `grep` through the CoreGraphics framework's symbols (as generated
by `nm -pam`) on "reconfig" (from
`CGSReconfigNotifierCalloutListInvokeAll` in the crash stacks), you
find the following two exported symbols:

        CGDisplayRegisterReconfigurationCallback
        CGDisplayRemoveReconfigurationCallback

Both of these are documented in Apple's [Quartz Display Services
Reference](https://developer.apple.com/library/mac/#documentation/graphicsimaging/reference/Quartz_Services_Ref/Reference/reference.html).
So now I had an explanation of what was going on as the crashes were
happening.  One or more apps had registered to receive notifications
for "graphics switching", and the crashes were happening as the OS was
delivering those notifications.  What if Flash were one of those apps?

I wrote an interpose library and found out that this is true.  But
though Apple's docs say you should balance every call to
`CGDisplayRegisterReconfigurationCallback` with one to
`CGDisplayRemoveReconfigurationCallback`, Flash only ever called
`CGDisplayRegisterReconfigurationCallback`.

I couldn't yet reproduce the crashes, so it took me a while to realize
the significance of this.  But I was quite sure this was a
use-after-free bug, so I eventually remembered that `libgmalloc` is a
good tool for resolving this kind of bug -- it tends to make you crash
as soon as any illegal access is attempted.

[libgmalloc](http://developer.apple.com/library/mac/#technotes/tn2124/_index.html#//apple_ref/doc/uid/DTS10003391-CH1-SECGMALLOC)

For reasons that I don't fully understand, `libgmalloc` doesn't get
along with Mozilla's `jemalloc`.  So you need to turn `jemalloc` off,
by setting the `NO_MAC_JEMALLOC` environment variable.

It was very easy to reproduce these crashes with `libgmalloc`.  Once I
could do this, it was also easy to see that Flash was at fault, and to
come up with a plausible explanation:

Every time a new Flash plugin was loaded, Flash called
`CGDisplayRegisterReconfigurationCallback` with a pointer to a
callback (always the same address) and a userInfo pointer (in fact a
pointer to a `CGLContextObj`, always different).  When the OS called
the callback, Flash would set up a stack frame and jump to (not call)
the address of the OS-provided `CGLUpdateContext()` method, which
takes one parameter -- a `CGLContextObj`.  But Flash didn't call
`CGDisplayRemoveReconfigurationCallback` when the plugin instance was
destroyed.  So on future calls to the callback from the OS, the
userInfo pointer pointed to random memory, which was potentially
invalid.

`CGLUpdateContext()`, like the other CGL methods, checks the validity
of any `CGLContextObj` passed to it, and does nothing with an object
that appears invalid.  So calling it with a random pointer doesn't
usually cause trouble -- as long as the pointer points to valid
memory.  But using `libgmalloc` ensured that these pointers to freed
memory would always point to an invalid address.

Flash's reconfiguration callback **jumps** to `CGLUpdateContext()`
after setting up a stack frame -- it doesn't **call**
`CGLUpdateContext()`.  This is why the callback didn't appear in any
of the crash stacks.

Flash only registered a reconfiguration callback on OS X 10.8.X -- not
on Lion or SnowLeopard.  This is why these crashes only happened on
Mountain Lion.  (The current Flash version, in which this bug is
fixed, registers a configuration callback on both OS X 10.7.5 and OS X
10.8.X.)

Flash doesn't register a reconfiguration callback when running in
Safari or Chrome -- only in Firefox or Opera.  So even on Mountain
Lion these crashes only happened in Firefox and Opera.
