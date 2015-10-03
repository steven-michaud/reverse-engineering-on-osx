CC=/usr/bin/clang++

interpose.dylib : interpose.o
	$(CC) -arch i386 -arch x86_64 -o interpose.dylib interpose.o \
		-lobjc -framework Cocoa -framework Carbon \
		-Wl,-F/System/Library/PrivateFrameworks -framework CoreSymbolication \
		-dynamiclib

interpose.o : interpose.mm
	$(CC) -arch i386 -arch x86_64 -o interpose.o \
		-Wno-deprecated-declarations -c interpose.mm

clean :
	rm interpose.o interpose.dylib
