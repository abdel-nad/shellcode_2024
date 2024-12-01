section .data
    usage_msg db "Usage: ./program <file.elf>", 0xA, 0
    usage_len equ $ - usage_msg

    msg_error_open db "Failed to open file", 0xA, 0
    msg_error_open_len equ $ - msg_error_open

    msg_error_map db "Failed to map file", 0xA, 0
    msg_error_map_len equ $ - msg_error_map

    msg_error_invalid db "Not a valid ELF file", 0xA, 0
    msg_error_invalid_len equ $ - msg_error_invalid

    msg_no_pt_note db "No PT_NOTE segment found", 0xA, 0
    msg_no_pt_note_len equ $ - msg_no_pt_note

    msg_success db "PT_NOTE segment successfully converted to PT_LOAD.", 0xA, 0
    msg_success_len equ $ - msg_success

section .bss
    filename resb 256         ; Buffer pour le nom du fichier
    elf_data resq 1           ; Adresse du fichier mappé
    file_size resq 1          ; Taille du fichier
    fd resq 1                 ; Descripteur de fichier
    phdr_offset resq 1        ; Offset de la table des en-têtes de programme
    phdr_num resw 1           ; Nombre d'entrées dans la table des en-têtes
    phdr_size resw 1          ; Taille d'une entrée

section .text
    global _start

_start:
    ; Vérifier les arguments (argc != 2)
    mov rdi, [rsp]          ; argc
    cmp rdi, 2
    jne print_usage

    ; Charger le nom du fichier (argv[1])
    mov rsi, [rsp + 8]      ; argv[1]
    mov rdi, filename       ; Destination
    call copy_string

    ; Ouvrir le fichier (open)
    mov rdi, filename       ; Nom du fichier
    mov rsi, 2              ; O_RDWR
    xor rdx, rdx            ; Mode (non utilisé)

   mov rdi, 1              ; stdout
   mov rsi, filename       ; buffer contenant le nom du fichier
   mov rdx, 256            ; taille maximale
   call write

    mov rax, 2              ; syscall: open
    syscall
    test rax, rax
    js handle_error_open
    mov [fd], rax           ; Sauvegarder le fd

    ; Obtenir la taille du fichier (lseek)
    mov rdi, rax            ; fd
    xor rsi, rsi
    mov rdx, 2              ; SEEK_END
    mov rax, 8              ; syscall: lseek
    syscall
    test rax, rax
    js handle_error_open
    mov [file_size], rax    ; Sauvegarder la taille du fichier

    ; Mapper le fichier en mémoire (mmap)
    xor rdi, rdi            ; NULL (adresse recommandée)
    mov rsi, rax            ; Taille du fichier
    mov rdx, 3              ; PROT_READ | PROT_WRITE
    mov r10, 1              ; MAP_SHARED
    mov r8, [fd]            ; fd
    xor r9, r9              ; Offset 0
    mov rax, 9              ; syscall: mmap
    syscall
    test rax, rax
    js handle_error_map
    mov [elf_data], rax     ; Sauvegarder l'adresse mappée

    ; Vérifier l'en-tête ELF
    mov rsi, rax            ; Adresse mappée
    cmp byte [rsi], 0x7F    ; EI_MAG0
    jne handle_error_invalid
    cmp dword [rsi + 1], 0x454C46 ; "ELF" dans EI_MAG1, EI_MAG2, EI_MAG3
    jne handle_error_invalid

    ; Récupérer les informations sur les en-têtes de programme
    mov rdi, rsi
    mov rax, [rdi + 0x20]   ; e_phoff
    mov [phdr_offset], rax
    movzx eax, word [rdi + 0x38] ; e_phnum
    mov [phdr_num], ax
    movzx eax, word [rdi + 0x36] ; e_phentsize
    mov [phdr_size], ax

    ; Parcourir la table des en-têtes de programme
    mov rcx, [phdr_num]     ; Nombre d'entrées
    mov rsi, [elf_data]     ; Adresse ELF
    add rsi, [phdr_offset]  ; Offset de la table
find_pt_note:
    cmp rcx, 0
    je no_pt_note_found
    cmp dword [rsi], 4      ; PT_NOTE
    je convert_to_pt_load
    add rsi, [phdr_size]    ; Passer à l'entrée suivante
    loop find_pt_note

convert_to_pt_load:
    mov dword [rsi], 1      ; PT_LOAD
    mov dword [rsi + 4], 5  ; PF_R | PF_X
    mov qword [rsi + 0x10], 0x0C000000 ; Nouvelle adresse virtuelle
    xor rax, rax
    mov qword [rsi + 0x20], rax ; p_filesz = 0
    mov qword [rsi + 0x28], rax ; p_memsz = 0
    mov qword [rsi + 0x30], 0x200000 ; p_align
    jmp success

no_pt_note_found:
    mov rdi, 1              ; fd (stdout)
    mov rsi, msg_no_pt_note
    mov rdx, msg_no_pt_note_len
    call write
    jmp cleanup

success:
    mov rdi, 1              ; fd (stdout)
    mov rsi, msg_success
    mov rdx, msg_success_len
    call write

    ; Synchroniser (msync)
    mov rdi, [elf_data]     ; Adresse mappée
    mov rsi, [file_size]    ; Taille
    xor rdx, rdx            ; Flags = 0
    mov rax, 26             ; syscall: msync
    syscall

cleanup:
    ; Nettoyer (munmap)
    mov rdi, [elf_data]     ; Adresse mappée
    mov rsi, [file_size]    ; Taille
    mov rax, 11             ; syscall: munmap
    syscall

    ; Fermer le fichier
    mov rdi, [fd]           ; fd
    mov rax, 3              ; syscall: close
    syscall

exit_program:
    xor rdi, rdi
    mov rax, 60             ; syscall: exit
    syscall

print_usage:
    mov rdi, 1              ; fd (stdout)
    mov rsi, usage_msg
    mov rdx, usage_len
    call write
    jmp exit_program

handle_error_open:
    mov rdi, 1              ; fd (stdout)
    mov rsi, msg_error_open
    mov rdx, msg_error_open_len
    call write
    jmp cleanup

handle_error_map:
    mov rdi, 1              ; fd (stdout)
    mov rsi, msg_error_map
    mov rdx, msg_error_map_len
    call write
    jmp cleanup

handle_error_invalid:
    mov rdi, 1              ; fd (stdout)
    mov rsi, msg_error_invalid
    mov rdx, msg_error_invalid_len
    call write
    jmp cleanup

copy_string:
    mov rcx, 256
copy_loop:
    lodsb
    stosb
    test al, al
    jz copy_done
    loop copy_loop
copy_done:
    ret

write:
    mov rax, 1              ; syscall: write
    syscall
    ret

