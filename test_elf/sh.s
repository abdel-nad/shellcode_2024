section .data
binsh db "/bin/sh", 0

section .text
global _start

_start:
    ; Ouvrir un shell
    xor rdi, rdi
    mov rsi, rdi
    mov rdx, rdi
    mov rax, 59        ; syscall execve
    lea rdi, [rel binsh] ; Charger l'adresse de `binsh` de manière relative
    syscall
