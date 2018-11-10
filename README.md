# Jailbreak Me 13.37
A webbased jailbreak solution unifying existing jailbreak me solutions and new ones.

Created by Sem Voigtländer

Please read ```RULES.md``` as well

## Support

- 8.4.1 & 9.3 up to 9.3.3 & 11.3.1 & 12.0 - 12.0.1 (64-bit)
- 3.1.2 up to 4.0.1 & 8.4.1 and 9.1 up to 9.3.4 (32-bit)

Read more: https://github.com/MTJailed/jailbreakme/blob/master/SUPPORT.md

## How it works
Using ModularJS various modules are loaded at runtime.

These modules can be divided into the following stages:

### 1. Identification
- Uses an information leakage (not vulnerability) in WebGL to detect the GPU of the victim device
- Uses the browser agent to define what browser and firmware to exploit
- Uses size and resolution constraints to detect the specific victim device
- Uses various debugging information about the hardware environment using window.performance or window.navigator
- Uses benchmarking algorithms and hashing to identify and track the victim device.

### 2. Eligibility
- Using the identification information the victim is checked against various constraints, such as whether the victim is a mobile device or a desktop.

### 3. Strategy selection
- Based on the eligibility constraints and identity the exploit strategy will be selected for the victim device and loaded.

### 4. Payload retrieval
- The strategy will load the payload(s) for the victim device, on iOS this can be for example Cydia, on desktops for example a remote administration tool.
- The payload is aligned so it can be used later when the exploit has created an executable region.

### 5. Exploitation
- The exploit is started and carefully sets up read/write primitives in the browser memory.
- Once r/w is gained an executable region is created and the payload is aligned / copied into it.
- The exploit jumps to the shellcode and starts executing it

### 6. Post-Exploitation
- Various tools and capabilities could be setup after successful completion of the exploit, such as a telnet client to gain a shell on the victim from the browser.

## Credits
- kudima https://github.com/kudima
- 5aelo https://twitter.com/5aelo
- Niklas B https://twitter.com/_niklasb
- Tihmstar https://twitter.com/tihmstar
- Coolstar https://twitter.com/coolstarorg
- Luca Todesco https://twitter.com/qwertyoruiopz
- KJC Research 
- Comex 
- PanguTeam https://twitter.com/panguteam
- Ian Beer https://twitter.com/i4nbeer
- Argp https://twitter.com/_argp
- Evad3rs 
- Jonathan Levin (For the jailbreak toolkit)
- Lokihardt (For being able to pwn browsers within a wink)
- Sem Voigtländer (just a techie)
- (@wwwtyro) https://github.com/wwwtyro/cryptico
