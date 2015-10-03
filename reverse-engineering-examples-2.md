# Example 2: Locating the Source of a Problem Using an Error Message

This example comes from [WebRTC crash]
(https://bugzilla.mozilla.org/show_bug.cgi?id=837539), which concerned
a crash deep in system code (in QTKit framework code) triggered by a
WebRTC code testcase.

* [`Makefile`](examples2/Makefile)
* [`interpose.mm`](examples2/interpose.mm)

On some systems (e.g. a Retina MacBook Pro running OS X 10.7.5) there
were no crashes, but the following error message appeared in the
console:

        CMIO_Graph.cpp:8709:HandleRenderNotify CMIOGraph::HandleRenderNotify()
        called but graph is not initialized!

I figured it might be useful to know which module was displaying this
error message, so I grepped in `/System/Library` for what I hoped was
a distinctive part of the error message:

        cd /System/Library
        grep -r -s "but graph is not initialized" *

I found a match in the following framework:

        /System/Library/Frameworks/CoreMediaIO.framework

Next I searched for "initialize" among this framework's symbols (the
output of `nm -pam`).  I found a number of matches, but two in
particular looked interesting, which were among the "external" (aka
exported) symbols (those that can be called from another module):

        CMIOGraphInitialize
        CMIOGraphUninitialize

I hooked these methods in an interpose library -- first to see if
they're called while running [bug
837539's](https://bugzilla.mozilla.org/show_bug.cgi?id=837539)
testcase, and second to see if disabling one or both made any
difference.

Both of these methods are undocumented, so first I needed to find
their calling parameters and return values.  I started by loading the
CoreMediaIO framework into Hopper Disassembler and looking at the
assembly code for each of these methods.  I found that each seemed to
take a single pointer parameter and returned an `int32_t` (in 64-bit
code, each method seemed to take a single parameter in `$rdi` and
return a value in `$eax`).

By trial and error I found that I could make the error messages and
crashes go away by disabling `CMIOGraphUninitialize()` but not
`CMIOGraphInitialize()`.  I also found that the "bad" call to
`CMIOGraphUninitialize()` was happening on a secondary thread, and
thus presumably "too early".  The key to fixing the bug turned out to
be that you need to make the call to `CMIOGraphUninitialize()` (and
the call that triggers it) always happen on the main thread.
