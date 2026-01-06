# is_ntdll

Simple heuristic to detect if a given file is "ntdll.dll".

## Build

### Using Docker (Recommended)

<pre>
    $ make build-image
    $ make build
</pre>

### Using Mingw on Linux/OSX Directly

<pre>
	$ x86_64-w64-mingw32-gcc -m64 -o bin/is_ntdll_amd64.exe src/main.c -Wall -Wextra -std=c99 -static -Wno-missing-field-initializers -Wno-cast-function-type -Wno-unused-label -Wno-unused-parameter -masm=intel -Os -s -ffunction-sections -fdata-sections -fno-ident -lshlwapi

	$ i686-w64-mingw32-gcc -m32 -o bin/is_ntdll_x86.exe src/main.c -Wall -Wextra -std=c99 -static -Wno-missing-field-initializers -Wno-cast-function-type -Wno-unused-label -Wno-unused-parameter -masm=intel -Os -s -ffunction-sections -fdata-sections -fno-ident -lshlwapi
</pre>