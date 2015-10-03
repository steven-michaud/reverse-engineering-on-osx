# Example 3: Finding Out How Flash Detects Graphics Hardware

This example comes from [Flash player crash with Intel GMA 950/X3100
GPUs] (https://bugzilla.mozilla.org/show_bug.cgi?id=804606),
concerning crashes in system code that occurred only with the Flash
plugin, and only with certain kinds of graphics hardware -- which were
unfortunately very difficult to find and test with.

* [`Makefile`](examples3/Makefile)
* [`interpose.mm`](examples3/interpose.mm)

The crashes happened in Flash code.  So it seemed likely that this was
a Flash bug, and that Flash behaved differently with the "wrong" kinds
of graphics hardware.  But there was no proof.

These crashes weren't reproducible.  So I wanted to find out as much
as possible about the code path on which they happened, and maybe use
that information to learn how to reproduce them.  One approach would
be to learn how to fool Flash into thinking that it was running on the
"wrong" hardware.  For this I needed to learn how Flash detects what
graphics hardware it's running on.

From Socorro crash logs I had the names of the two different kinds of
graphics hardware (Intel GMA 950 and Intel GMA X3100).  Those crash
logs referred to the following two Apple video drivers:

        AppleIntelGMAX3100GLDriver
        AppleIntelGMA950GLDriver

I grepped the Flash plugin for "X3100", "GMA" and "950" and found
nothing relevant.  Then I tried grepping in `/System/Library/` for
"X3100".  I found seemingly relevant matches in several different
locations, including several kernel extensions and the AGL framework.
But the match I thought most likely to be helpful was in the OpenGL
framework.  (I already knew Flash defaulted to using OpenGL.)

        /System/Library/Frameworks/OpenGL.framework/Headers/CGLRenderers.h
          #define kCGLRendererIntelX3100ID     0x00024200

Looking at CGLRenderers.h directly, I found that it doesn't contain
any unambiguous reference to the Intel GMA 950, though it does contain
the following line:

          #define kCGLRendererIntel900ID       0x00024000

I looked these up on the web, and found that they're "renderer IDs",
documented in Apple's [CGL
Reference](https://developer.apple.com/library/mac/#documentation/graphicsimaging/reference/CGL_OpenGL/Reference/reference.html).
A "renderer ID" is one of the properties of a "renderer" that can be
queried using the documented `CGLDescribeRenderer()` method.

I hooked this method using an interpose library and found that Flash
does use it to query a "renderer"'s `kCGLRPRendererID` property, and
also that Flash changes its behavior if you change this method to
always return that the `kCGLRPRendererID` is
`kCGLRendererIntelX3100ID` or `kCGLRendererIntel900ID`.  Instead of
using NPAPI CoreAnimation drawing model (which it does by default), on
this hardware Flash falls back to using the CoreGraphics drawing
model.
