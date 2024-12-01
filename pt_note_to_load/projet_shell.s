section .data
    signature db 0x7F, "ELF"             ; Signature ELF à comparer
    invalid_msg db "Erreur : pas un fichier ELF.", 10
    valid_msg db "Validé : fichier ELF détecté.", 10
    invalid_len equ $ - invalid_msg      ; Longueur du message d'erreur
    valid_len equ $ - valid_msg          ; Longueur du message de succès

section .bss
    file_header resb 16                  ; Buffer pour les premiers octets du fichier

section .text
global _start

_start:
    ; Ouvrir le fichier en lecture seule
    mov rax, 2                           ; sys_open
    pop rdi                              ; Premier argument du programme (nom du fichier)
    xor rsi, rsi                         ; Mode O_RDONLY
    syscall                              ; Appel du syscall pour ouvrir le fichier

    ; Vérifier si le fichier s'est ouvert correctement
    test rax, rax                        ; Vérifier le code de retour
    js quit                              ; Si erreur (descripteur négatif), quitter
    mov rdi, rax                         ; Sauvegarder le descripteur de fichier

    ; Lire les 16 premiers octets du fichier
    mov rax, 0                           ; sys_read
    lea rsi, [file_header]               ; Buffer où lire les octets
    mov rdx, 16                          ; Lire 16 octets
    syscall                              ; Appeler le syscall de lecture

    ; Comparer les 4 premiers octets avec la signature ELF
    lea rsi, [file_header]               ; Charger le buffer lu
    lea rdi, [signature]                 ; Charger la signature ELF
    mov rcx, 4                           ; Nombre d'octets à comparer
    repe cmpsb                           ; Comparer les octets un par un
    jne invalid                          ; Si échec, aller à l'étiquette d'erreur

valid:
    ; Afficher le message de succès
    mov rax, 1                           ; sys_write
    mov rdi, 1                           ; stdout
    lea rsi, [valid_msg]                 ; Message de succès
    mov rdx, valid_len                   ; Longueur du message
    syscall                              ; Afficher le message
    jmp quit                             ; Quitter proprement

invalid:
    ; Afficher le message d'erreur
    mov rax, 1                           ; sys_write
    mov rdi, 1                           ; stdout
    lea rsi, [invalid_msg]               ; Message d'erreur
    mov rdx, invalid_len                 ; Longueur du message
    syscall                              ; Afficher le message

quit:
    ; Quitter le programme
    mov rax, 60                          ; sys_exit
    xor rdi, rdi                         ; Code de sortie 0
    syscall                              ; Appeler le syscall de sortie

