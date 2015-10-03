# Resources

## Documentation

1. Apple documentation
   * [Mac debugging
     techniques](http://developer.apple.com/technotes/tn2004/tn2124.html)
   * [Current documents, search by
     title](https://developer.apple.com/library/mac/navigation/)
   * ["Retired" documents, search by
     title](http://developer.apple.com/legacy/library/navigation/)

2. Calling conventions (stack frames and registers)
   <p>Basic information is scattered through [the Mac debugging
   techniques
   article](http://developer.apple.com/technotes/tn2004/tn2124.html).
   Much fuller information is available here:
   * [OS X ABI Function Call
     Guide](http://developer.apple.com/library/mac/#documentation/DeveloperTools/Conceptual/LowLevelABI/000-Introduction/introduction.html)
   * [AMD64 Processor ABI](http://x86-64.org/documentation/abi.pdf)

3. X86/X86_64 assembly instructions
   * [X86 Instruction Listings](http://en.wikipedia.org/wiki/X86_instruction_listings)
   * [Intel Instruction Set
     Reference](http://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf)

## Other Resources

1. [`class-dump`](http://stevenygard.com/projects/class-dump/)

    This excellent utility dumps the equivalent of full header
    information from an Objective-C binary.

2. Disassemblers

    I can't find any decent open-source disassemblers, but Hopper
    Disassembler is decent and not too expensive.  It's very good at
    following cross-references, so that (for example) you can find
    both a method's implementation and the code it's called from.

    [Hopper Disassembler](http://www.hopperapp.com/)

    You can also get a reasonably good assembly code listing of a
    particular function in a binary using

    `otool -t -v -V -p function_name binary`

3. [Apple Open Source](http://opensource.apple.com/)

    Apple makes the source-code available for significant parts of OS
    X, which can be very useful for tracing undocumented behavior --
    for example dyld, libobjc, gcc, clang, llvm and xnu (the Mach
    kernel).

4. Interpose libraries
   <p>These are small libraries that can be used to hook C/C++ methods
   or swizzle Objective-C methods in running, unaltered applications.
   I've written a template which is included in this package:
   * [`Makefile`](InterposeLibraryTemplate/Makefile)
   * [`interpose.mm`](InterposeLibraryTemplate/interpose.mm)

5. CoreSymbolication framework

    An undocumented Apple framework, available on SnowLeopard (OS X
    10.6) and up, that can be used to programmatically examine the
    call stack in a running program -- for example to display a trace
    of the current call stack.

    The best source for how to use this is my interpose library
    template from item 4 above.

6. `gdb`

    `gdb` is Apple's default command-line debugger on OS X 10.8.5 and
    below.  I don't know of any really good documentation for using
    it.  I generally rely on its internal documentation and search on
    the web (as the need arises) for whatever that doesn't cover.

    The [Mac Debugging Techniques
    article](http://developer.apple.com/technotes/tn2004/tn2124.html)
    does have a lot of information on Apple-specific additions to
    `gdb`, though.

7. `lldb`

    `lldb` is Apple's default command-line debugger on OS X 10.9.5 and
    up.  It has even less documentation than `gdb`, and the internal
    documentation is very spotty.

    I find I rely heavily on the [LLDB to GDB Command
    Map](http://lldb.llvm.org/lldb-gdb.html)
