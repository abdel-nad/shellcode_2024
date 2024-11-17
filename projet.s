section .data
fichier db "text.txt", 0
;buffer resb 256

section .bss
fd resq 1
buffer resb 256

section .text
global _start

_start:
	mov rax,2
	lea rdi, [fichier]
	mov rsi, 2
	xor rdx, rdx
	syscall 
	mov [fd], rax

	mov rax, 0
	mov rdi, [fd]
	lea rsi, [buffer]
	mov rdx, 256
	syscall
	mov r8, rax	

	mov rax, 1
	mov rdi, 1
	lea rsi, [buffer]
	mov rdx, r8
	syscall

	mov rax, 3
	mov rdi, [fd]
	syscall

	mov rax, 60
	xor rdi, rdi
	syscall	
