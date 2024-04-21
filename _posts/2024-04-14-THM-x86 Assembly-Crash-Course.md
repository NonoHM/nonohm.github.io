---
layout: post
title: THM x86 Assembly Crash Course
tags: [THM, Malware Analysis, x86 Assembly]
author: NonoHM
date: 2024-04-14 16:52:32
toc:
    sidebar: left
    toc-depth: 3
---


## Task 1 - Introduction

The assembly language is the lowest level of human-readable language and is also the highest level of language into which a binary can be reliably decompiled. That is why knowing the basics of the assembly language is essential when doing reverse engineering because malware samples are most likely to be compiled binaries.
The two options are decompiling or disassembling but the problem with disasembling is that a lot of information in the source code is removed, thus natural names for variables or functions are changed in the compiling process. That is why the most reliable code we have is assembly code.

### Learning Objectives

We will be covering the following topics:

- Opcodes and operands
- General assembly instructions
- Arithmetic and logical instructions
- Conditionals
- Branching instructions

## Task 2 - Opcodes and Operands

The code of a program to be executed by the CPU needs to be written ion its binary form, so it is a sequence of 1s and 0s. To be understandable for humans, the instructions are gathered into groups of 8 bits to form a byte and one byte form 2 hex digits. Among these, there are opcodes and operands; opcodes represent the actual operations and operands represent the registers, memory locations or immediate values on which the operations are performed.

### Opcodes

Like said before, Opcodes are numbers that correspond to instructions performed by the CPU. A disassembler reads opcodes and translates them into human readable text.

An example of instruction that moves the number `0x5f` (95 in decimal form) into *eax* register:

``` asm
040000:    b8 5f 00 00 00    mov eax, 0x5f
```

- `040000`: Address where the instruction is located
- `b8`: Opcode `mov eax`
- `5f 00 00 00`: Operand `0x5f`

> Note
> In little-endian, the instruction would be written `b8 00 00 00 5f`.

### Types of Operands

In general, there are three types of operands in ASM:

- **Immediate Operands**: Fixed values like `0x5f`.
- **Registers**: Registers are operands like `eax`
- **Memory Operands**: They are denoted by square brackets and reference memory locations. `[eax]` signifies the value present in `eax`.

### Questions

**What are the hex codes that denote the assembly operations called?**

*Answer: `Opcodes`*

**Which type of operand is denoted by square brackets?**

*Answer: `Memory Operands`*

## Task 3 - General Instructions

Instructions tell the CPU what operation to perform and operands are used to store results into register or memory.

**`mov` instruction**

The mov instruction moves a value from one location to another. The syntax is:

``` asm
mov destination, source
```

The mov instruction can move a fixed value to a register, a register to another register, or a value in a memory location to a register.

- **Fixed value to register**: `mov eax, 0x5f`
- **Value stored in register to register**: `mov eax, ebx`
- **Value stored in memory location to register**: `mov eax, [0x5fccbe]` or `mov eax, [ebx]` or `mov eax, [ebx+4]` 

*Value stored in memory location to register explained*

The first example takes the value stored in `0x5fccbe` to `eax`.
The second example takes the value stored into the memory address, contanied into `ebx` to eax.
Example:

``` asm
mov ebx, 0x5fccbe
mov eax, [ebx]
; = mov eax, [0x5fccbe]
```

The third example does the same thing with an offset of 4 in the memory location like `[0x5fccbe+4]`.

**`lea` instruction**

The lea instruction stands for *load effective address*. While the mov instruction moves the data from the source to the detsination, the lea instruction moves the memory address of the source to the destination. The syntax is:

``` asm
lea destination, source
```

Here, `lea eax, [ebp+4]` moves the memory address located into `ebp` and adds 4.

**`nop` instruction**

nop stands for no operation because it moves eax value into itself, resulting in no meaningful opreation. The nop instructions are used for consuming CPU cycles while waiting for an operation or other such purposes. The syntax is:

``` asm
nop
```

**Shift instructions**

Shift instructions serve to shift each bit to left or right by adding a certain number of 0s at the start or at the end. The syntax is:

``` asm
shr destination, count
shl destination, count
```

This means overflowing is possible like:

``` asm
mov eax, 0x00000101
shr eax, 1
; eax => 0x00000010 and CR Flag is set to 1
```

**Rotate instructions**

Rotate instructions are similar to the shift ones; the bits are shifted to the left or right but the end bit of the value returns back to the start if the shift goes to the right and the first bit returns back to the end if the shift goes to the left. The syntax is:

``` asm
ror destination, count
rol destination, count
```

Examples:

``` asm
; Right shift
mov eax, 0b00000101 ; or 0x05
ror eax, 1
; eax => 0b10000010 or 0x82

; Left shift
mov ebx, 10100000 , or 0xa0
rol ebx, 1
; ebx => 01000001 or 0x41
```

### Questions

**In mov eax, ebx, which register is the destination operand?**

*Answer: `eax`*

**What instruction performs no action?**

*Answer: `nop`*

##  Task 4 - Flags

In x86 assembly language, CPU has several flags that indicate the outcome of certain operations or conditions which are stored in EFLAGS/RFLAGS register.

|       Flag       | Abbreviation |                                                                    Explanation                                                                    |
|:----------------:|:------------:|:-------------------------------------------------------------------------------------------------------------------------------------------------:|
|       Carry      |      CF      |  Set when a carry-out or borrow is required from the most significant bit in an arithmetic operation. Also used for bit-wise shifting operations. |
|      Parity      |      PF      |                                 Set if the least significant byte of the result contains an even number of 1 bits.                                |
|     Auxiliary    |      AF      |                     Set if a carry-out or borrow is required from bit 3 to bit 4 in an arithmetic operation (BCD arithmetic).                     |
|       Zero       |      ZF      |                                                    Set if the result of the operation is zero.                                                    |
|       Sign       |      SF      |                               Set if the result of the operation is negative (i.e., the most significant bit is 1).                               |
|     Overflow     |      OF      |            Set if there's a signed arithmetic overflow (e.g., adding two positive numbers and getting a negative result or vice versa).           |
|     Direction    |      DF      | Determines the direction for string processing instructions. If DF=0, the string is processed forward; if DF=1, the string is processed backward. |
| Interrupt Enable |      IF      |                           If set (1), it enables maskable hardware interrupts. If cleared (0), interrupts are disabled.                           |

Flags can be used in conditional jumps and are crucial for implementing conditional branching in assembly code.

### Questions

**Which flag will be set if the result of the operation is zero? (Answer in abbreviation)**

*Answer: `ZF`*

**Which flag will be set if the result of the operation is negative? (Answer in abbreviation)**

*Answer: `SF`*

##  Task 5 - Arithmetic and Logical Instructions

### Arithmetic Instructions

**Addition and Subtraction Instructions**

In the addition instruction, the value is added to the destination and then stored into it. The syntax is:

``` asm
add destination, value
; x = x + value
```

In the substraction instruction, the destination is substracted by the value and then stored into the destination. The syntax is:

``` asm
sub destination, value
; x = x - value
```

The value can be a constant or a register. For substraction, ZF is set if the result is zero and CF is set if the destination is smaller than the value.


**Multiplication and Division Instructions**

The multiplication and division operations use the eax and edx registers.

The multiply instruction has the following syntax:

``` asm
mul value
```

It multiplies the value with the one stored into `eax `and stores the result into `edx:eax`, beceause the multiplication of two 32-bit values can often result in higher ones. The lower bits are in `eax` and the higher bits are in `edx`.

Tha value can be another register or a constant.

The division instruction has the following syntax:

``` asm
div value
```

It divides the 64-bit value in `edx:eax` and saves the result in `eax` and the reminder in `edx`.

**Increment and Decrement Instructions**

These instructions increment or decrement the operand by 1. The syntax is:

``` asm
inc eax ; Increase by 1
dec eax ; Decrease by 1
```

### Logical Instructions

**AND instruction**

The AND intruction performs a bitwise (bit per bit) AND operation on the operands. 

| A | B | A AND B |
|---|---|---------|
| 0 | 0 |    0    |
| 0 | 1 |    0    |
| 1 | 0 |    0    |
| 1 | 1 |    1    |

The syntax is:

``` asm
and destination, source
; mv ax, 0x0000
; and ax, 0xFFFF
; => ax = 0x0000
```

**OR instruction**

The OR intruction performs a bitwise (bit per bit) OR operation on the operands. 

| A | B | A OR B |
|---|---|--------|
| 0 | 0 |   0    |
| 0 | 1 |   1    |
| 1 | 0 |   1    |
| 1 | 1 |   1    |

The syntax is:

``` asm
or destination, source
; mv ax, 0x0000
; or ax, 0xFFFF
; => ax = 0xFFFF
```

**NOT Instruction**

The NOT instruction takes one operand and simply inverts the operand bits.

| A | NOT A |
|---|-------|
| 0 |   1   |
| 1 |   0   |

The syntax is:

``` asm
not operand
```

**XOR Instruction**

The XOR intruction performs a bitwise (bit per bit) XOR operation on the operands. 

| A | B | A XOR B |
|---|---|---------|
| 0 | 0 |    0    |
| 0 | 1 |    1    |
| 1 | 0 |    1    |
| 1 | 1 |    0    |

The syntax is:

``` asm
xor destination, source
; mv ax, 0x0000
; or ax, 0xFFFF
; => ax = 0xFFFF
```

### Questions

**In a subtraction operation, which flag is set if the destination is smaller than the subtracted value?**

*Answer: `Carry Flag`*

**Which instruction is used to increase the value of a register**

*Answer: `inc`*

**Do the following instructions have the same result? (yea/nay)**

``` asm
xor eax, eax
mov eax, 0
```
*Answer: `yea`*

## Task 6 - Conditionals and branching

### Conditionals

Conditional instructions determine if two values are equal to, greater than or less than each other.

**TEST Instruction**

The test instruction performs a bitwise AND operation and instead of storing the result in the destination, it sets the Zero Flag if the result is O. This is often used to check if an operand is a null value. The syntax is:

`test destination, source`

**CMP Instruction**

The CMP instruction compares two operands and sets the ZF or CF depending of the result. It works by performing a substration, then set the ZF if both operands are equal or CF if the source > destination. CF and ZF are clear if destination > source. The syntax is:

``` asm
cmp destination, source
```

### Branching

Branching changes the value of the Instruction Pointer in order to change program's flow.

**JMP Instruction**

The JMP instruction makes the IP jump to a specified location. The syntax is:

``` asm
jmp location ;Memory Address
```

**Conditional Jumps**

Conditional jumps decide to jump based on the Flag Registers values.

| Instruction | Explanation                                                                                                                                              |
|-------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|
| jz          | Jump if the ZF is set (ZF=1).                                                                                                                            |
| jnz         | Jump if the ZF is not set (ZF=0).                                                                                                                        |
| je          | Jump if equal. Often used after a CMP instruction.                                                                                                       |
| jne         | Jump if not equal. Often used after a CMP instruction.                                                                                                   |
| jg          | Jump  if the destination is greater than the source operand. Performs signed  comparison and is often used after a CMP instruction.                      |
| jl          | Jump if the destination is lesser than the source operand. Performs signed comparison and is often used after a CMP instruction.                         |
| jge         | Jump  if greater than or equal to. Jumps if the destination operand is  greater than or equal to the source operand. Similar to the above  instructions. |
| jle         | Jump  if lesser than or equal to. Jumps if the destination operand is lesser  than or equal to the source operand. Similar to the above instructions.    |
| ja          | Jump if above. Similar to jg, but performs an unsigned comparison.                                                                                       |
| jb          | Jump if below. Similar to jl, but performs an unsigned comparison.                                                                                       |
| jae         | Jump if above or equal to. Similar to the above instructions.                                                                                            |
| jbe         | Jump if below or equal to. Similar to the above instructions.                                                                                            |


### Questions

**Which flag is set as a result of the test instruction being zero?**

*Answer: `Zero Flag`*

**Which of the below operations uses subtraction to test two values? 1 or 2?**

1. cmp eax, ebx
2. test eax, ebx

*Answer: `1`*

**Which flag is used to identify whether a jump will be taken or not after a jz or jnz instruction?**

*Answer: `Zero Flag`*

## Task 7 - Stack and Function calls

### The Stack

We have already learnt that the stack is a LIFO (Last In, First Out) Memory. This means the last variable pushed onto the stack is the first to pop.

**PUSH Instruction**

The push instruction push the source operand onto the stack, becoming the top of the stack. The value of the memory location is pointed by the Stack Pointer (ESP). The syntax is:

``` asm
push source
```

- `pusha`: Pushes all 16-bit GP registers to the stack from AX to DI.
- `pushad`: Pushes all 32-bit GP registers to the stack from EAX to EDI.

**POP Instruction**

The pop instruction retrieves the value from the top of the stack and stores it in the destination operand. As a result, the ESP is also decremented, updated to point to the new top of the stack. The syntax is:

``` asm
pop destination
```

- `popa`: Pops all 16-bit GP registers from the stack from DI to AX.
- `popad`: Pops all 32-bit GP registers from the stack from EDI to EAX.

**CALL Instruction**

The `call` instruction is used to perform a function call. It saves the return address which is the one just after the `call` instruction by pushing it onto the stack, then it jumps to the specified address and begins executing from here. The syntax is:

`call location`

### Questions

**Which instruction is used for performing a function call?**

*Answer: `call`*

**Which instruction is used to push all registers to the stack?**

*Answer: `pusha`*

## Task 8 - Practice Time

Run instructions and observe the stack, memory and register on the Assembly Emulator.

### Questions

**While running the MOV instructions, what is the value of [eax] after running the 4th instruction? (in hex)**

*Answer: `0x00000040`*

**What error is displayed after running the 6th instruction from the MOV instruction section?**

*Answer: `Memory to memory data movement is not allowed.`*

**Run the instructions from the stack section. What is the value of eax after the 9th instruction? (in hex)**

*Answer: `0x00000025`*

**Run the instructions from the stack section. What is the value of edx after the 12th instruction? (in hex)**

*Answer: `0x00000010`*

Run the instructions from the stack section. After POP ecx, what is the value left at the top of the stack? (in hex)

*Answer: `0x00000010`*

Run the cmp and test instructions. Which flags are triggered after the 3rd instruction?
(Note: Use these abbreviations in alphabetical order with no spaces: CF,PF,SF,ZF)

*Answer: `PF,ZF`*

Run the test and the cmp instructions. Which flags are triggered after the 11th instruction?
(Note: Use these abbreviations in alphabetical order with no spaces: CF,PF,SF,ZF)

*Answer: `CF,SF`*

Run the instructions from the lea section. What is the value of eax after running the 9th instruction? (in hex)

*Answer: `0x0000004B`*

Run the instructions from the lea section. What is the final value found in the ECX register? (in hex)

*Answer: `0x00000045`*

## Task 9 - Conclusion

In this module, we've explored foundational concepts of x86 assembly language, focusing on essential instructions and operations. 
We learned how to convert opcodes into assembly language, and covered general instructions like move (mov), load effective address (lea), shift, and rotate. Additionally, we delved into arithmetic operations including addition, subtraction, multiplication, and division. We also discussed conditionals for branching, understanding how to control program flow based on conditions. Lastly, we explored stack operations (push and pop) and how they are used in function calls. 