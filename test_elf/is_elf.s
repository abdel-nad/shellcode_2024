section .data
    magic_bytes db 0x7F, "ELF"          ; Signature ELF standard
    err_msg db "Ce n'est pas un fichier ELF valide", 10
    ok_msg db "Fichier ELF valide trouvé", 10
    err_len equ $ - err_msg             ; Taille du message d'erreur
    ok_len equ $ - ok_msg               ; Taille du message de validation

section .bss
    header resb 16                      ; Espace pour lire l'en-tête ELF

section .text
global _start

_start:
    ; Ouvrir et lire l'en-tête du fichier
    mov rax, 2                          ; sys_open
    mov rdi, 0                          ; Nombre d'arguments
    pop rdi                             ; Nom du programme
    pop rdi                             ; Premier argument (nom du fichier)
    mov rsi, 0                          ; O_RDONLY
    syscall                             ; Appeler le syscall

    cmp rax, 0                          ; Vérifier si le descripteur de fichier est valide
    jl exit                             ; Si erreur, quitter le programme

    mov rdi, rax                        ; Charger le descripteur de fichier
    mov rax, 0                          ; sys_read
    mov rsi, header                     ; Adresse du buffer pour l'en-tête
    mov rdx, 16                         ; Lire les 16 premiers octets
    syscall                             ; Appeler le syscall

    ; Vérifier la signature ELF
    mov rsi, header                     ; Charger l'en-tête ELF
    mov rdi, magic_bytes                ; Charger la signature ELF attendue
    mov rcx, 4                          ; Comparer les 4 premiers octets
    repe cmpsb                          ; Comparer les octets
    jne not_elf                         ; Si différent, ce n'est pas un fichier ELF

    ; C'est un fichier ELF valide
    mov rax, 1                          ; sys_write
    mov rdi, 1                          ; stdout
    mov rsi, ok_msg                     ; Adresse du message de validation
    mov rdx, ok_len                     ; Taille du message
    syscall                             ; Écrire le message
    jmp exit                            ; Quitter le programme

not_elf:
    ; Ce n'est pas un fichier ELF
    mov rax, 1                          ; sys_write
    mov rdi, 1                          ; stdout
    mov rsi, err_msg                    ; Adresse du message d'erreur
    mov rdx, err_len                    ; Taille du message
    syscall                             ; Écrire le message

exit:
    ; Quitter le programme
    mov rax, 60                         ; sys_exit
    xor rdi, rdi                        ; Code de retour 0
    syscall                             ; Appeler le syscall

