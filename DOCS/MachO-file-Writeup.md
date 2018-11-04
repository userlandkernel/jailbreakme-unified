# The Mach-O File format
_This document contains information taken from https://github.com/kpwn/iOSRE/edit/master/wiki/Mach-O.md_  

A file format is a standard for how a file is structured.  
The Mach-O (MACH/MUCK Object) is a well-structured fileformat, the executable format of choice for XNU and dyld.  
It serves a purpose analog to what ELF or PE do; to put it simply, it describes a portion of an address space.  
Support for multi-architecture executables is also provided thanks to the fat format, which allows you to join multiple different architecture Mach-OS letting the kernel pick which to load. 
Note that it is possible to influence this with posix_spawn APIs.  
Mach-O Files have a header with info about the structure of the file such as the cpu type, file type and dynamic loader info.  
From there on the sections of the file can easily be found and analyzed to learn more about the file.  
Commandline utillities such as nm and strings use a mach-o parser to analyze the file.  

## Working with Mach-O Files
1. otool is provided out-of-the-box with the xcode cli utils.
2. jtool, by Jonathan Levin, author of MOXiI and MOXiI II, is an analog but more flexible and advanced tool. On the other hand, it lacks support for disassembling architectures other than arm64.
2. lipo is a tool for working with fat files
3. Apple headers, specifically `<mach-o/loader.h>`/`<mach-o/fat.h>`.
4. libmachoman.dylib (My very own parser library)

# General structure
This image from Apple documentation illustrates pretty well how a Mach-O file is composed.

The **header** is the first thing you will encounter while parsing a Mach-O file. It is always located at the very beginning.

Immediately following the header there are the **load commands**, these commands describe what the content of the file is. They give us an idea of how the file is structured. Particularly, each command describes its own **segment** a piece of data (located in the **data** part of the Mach-O file), specifying where it is located (offset) in the file, and its size. Each specific command may also contain other values, specific to its segment only.

Finally, we have the **data**. This part of the file contains actual data. It also contains, as you are probably wondering, the executable code of the Mach-O. The structure of this part is described exactly by the load commands discussed above, the layout is really the same. Each segment may be divided into various **sections** which simply exist to sub-categorize the data in each segment. For example, the `__TEXT` segment contains various sections, among those the `__text` section, that contains the actual executable machine bytes. Another section is the `__cstring`, which only contains hardcoded C strings used in the program.  

## Endianess
Endianness tells something about how data is read by the cpu.

You can read bytes from left to right or from right to left.

Big endian: (01 AB CD EF)

Little endian: (EF CD AB 01)

Mach-O Files can have multiple architectures and multiple endianness

## Magic
The magic is a magic 32-bit integer defining the start of a mach-o file.

The header of the file comes directly after.

There are the following magics that a mach-o file can have:

* 0xFEEDFACE (32-bit)
* 0xFEEDFACF (64-bit)
* 0xCEFAEDFE (little endian 32-bit)
* 0xCFFAEDFE (little endian 64-bit)


## Header
The header of a 32-bit Mach-O file looks like this (from mach-o/loader.h (opensource.apple.com):
```C
	struct mach_header {
		uint32_t	magic;		/* mach magic number identifier */
		cpu_type_t	cputype;	/* cpu specifier */
		cpu_subtype_t	cpusubtype;	/* machine specifier */
		uint32_t	filetype;	/* type of file */
		uint32_t	ncmds;		/* number of load commands */
		uint32_t	sizeofcmds;	/* the size of all the load commands */
		uint32_t	flags;		/* flags */
	};
```

From this you can get info about its endianness by looking at the magic, the cpu it was build for, the file type (Executable, Kernel Extension, Shared Library, etc.).


## Load Commands
Directly after the header the load commands start.

There are many load commands giving info about the file and LC_MAIN is the main load command.

## Segments
Segments are portions of the Mach-O file that get mapped in the address space at runtime. They are composed of sections, which hold actual data. 
Whatever data they contain, it is needed by the process at runtime and so it gets mapped in the address space.
(source: https://github.com/kpwn/iOSRE/blob/master/wiki/Mach-O.md)

## Sections
As we have stated before, segments are made of sections, and those hold actual data. They can contain virtually anything, like executable code bytes, data, pointers, strings or even nothing at all (see PAGEZERO segment).

## The strings table

## The symbol table

## The Objective-C info
