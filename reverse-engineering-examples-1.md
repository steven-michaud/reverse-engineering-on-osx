# Example 1: Figuring Out NSView Dirty Rects

This example comes from [nsChildView::WillPaint terribly inefficient
when drawing to
titlebar](https://bugzilla.mozilla.org/show_bug.cgi?id=861317).  Prior
to my patch for that bug, we caused the entire titlebar to be
repainted every time we painted any part of the browser window.  This
was terribly inefficient, and triggered a huge performance hit.

The titlebar (the top 22 pixels of every titled window) is (basically)
managed (and drawn) by the OS -- not by us.  But in order to support
drawing content in the titlebar (or rather in parts of it), we need to
partially take over management of it ourselves.  To do this properly,
we need to know at any time which parts of an `NSView` object are
"dirty" (need to be redrawn).

"Ordinary" Cocoa apps don't need to know this outside the `-[NSView
drawRect:]` method.  So OS X has no documented way to find this
information outside the `-[NSView drawRect:]` method.  But of course
OS X does need this information "under the hood", so it's there if you
know how to look for it.

* [`Makefile`](examples1/Makefile)
* [`interpose.mm`](examples1/interpose.mm)

1. Look at a class-dump of the `NSView` class.

    (Note that, strictly speaking, we need to examine header
    information for both the `NSView` class and the undocumented
    `_NSViewAuxiliary` class.  The latter is a structure that stores
    many of an `NSView` class's variables.)

    Search through the `NSView` and `_NSViewAuxiliary` classes' header
    information for objects that seem relevant -- for example that
    match "invalid" or "dirty".  "Invalid" has a number of hits, but
    none of them seem relevant.  "Dirty" has several hits that
    **might** be relevant.  We need to test them to be sure.

        @interface NSView
          - (struct CGRect)_dirtyRect;
          - (id)_dirtyRegion;
        @end

        @interface _NSViewAuxiliary
        {
          struct CGRect _dirtyRect;
          NSRegion *_dirtyRegion;
        }
        @end

2. Create an interpose library to hook `-[NSView _dirtyRect]` and
   `-[NSView _dirtyRegion]`

    This shows that most apps don't trigger the use of either of these
    methods.  But Google Chrome does (indirectly) use `-[NSView
    _dirtyRect]`.  And the output of running this interpose library in
    Google Chrome shows that it does what we need.

    Interestingly, my interpose library also shows that neither of the
    `_NSViewAuxiliary` variables gets used even in Google Chrome --
    both of them are always empty.  If you disassemble the OS X 10.7.5
    AppKit's `methImpl_NSView__dirtyRect` in Hopper Disassembler and
    also step through it in `gdb` (with step-mode on), you'll see that
    it usually bypasses `_NSViewAuxiliary._dirtyRect` altogether.  The
    code calls `_NSWindowsTrackDirtyRegions()`, and if that returns
    TRUE calls `-[NSWindow
    _copyNeedsDisplayRegionInRect:validateSubtractedRegion:]` on the
    NSView's NSWindow.

3. Test `-[NSRect _dirtyRect]` in Firefox.

    Test it in all supported versions of OS X.  Also check that its
    declaration is the same in class-dumps of the AppKit framework
    from all supported OS X versions, and as far back as you can
    check.

    The more "stable" an undocumented method is, the safer it is to
    use.
