# is_ntdll

Simple heuristic to detect if a given file is "ntdll.dll". This tool should be able to handle 32 and 64 bits versions of ntdll.

## Build

### Using Docker (Recommended)

<pre>
    $ make build-image
    $ make build
</pre>

### Using MinGW on Linux/OSX Directly

<pre>
	$ x86_64-w64-mingw32-gcc -m64 -o bin/is_ntdll_amd64.exe src/main.c -Wall -Wextra -std=c99 -static -Wno-missing-field-initializers -Wno-cast-function-type -Wno-unused-label -Wno-unused-parameter -masm=intel -Os -s -ffunction-sections -fdata-sections -fno-ident -lshlwapi
	$ i686-w64-mingw32-gcc -m32 -o bin/is_ntdll_x86.exe src/main.c -Wall -Wextra -std=c99 -static -Wno-missing-field-initializers -Wno-cast-function-type -Wno-unused-label -Wno-unused-parameter -masm=intel -Os -s -ffunction-sections -fdata-sections -fno-ident -lshlwapi
</pre>

## Usage

<pre>
    PS C:\> is_ntdll.exe C:\windows\system32\ntdll.dll
    TRUE
    PS C:\> is_ntdll.exe C:\windows\system32\user32.dll
    FALSE
</pre>