section .data
fichier db "text.txt", 0          ; Nom du fichier à ouvrir (terminé par un caractère nul)

section .bss
fd resq 1                         ; Descripteur de fichier (stocké ici après ouverture)
buffer resb 256                   ; Buffer pour stocker les données lues

section .text
global _start

_start:
	; Ouvrir le fichier
	mov rax, 2                     ; Appel système `open` (code 2)
	lea rdi, [fichier]             ; Adresse du nom du fichier
	mov rsi, 2                     ; Mode d'accès (lecture seule : O_RDONLY)
	xor rdx, rdx                   ; Pas de flags supplémentaires
	syscall                        ; Effectuer l'appel système
	mov [fd], rax                  ; Stocker le descripteur de fichier retourné

	; Lire les données du fichier
	mov rax, 0                     ; Appel système `read` (code 0)
	mov rdi, [fd]                  ; Descripteur de fichier
	lea rsi, [buffer]              ; Adresse du buffer pour stocker les données lues
	mov rdx, 256                   ; Nombre maximal d'octets à lire
	syscall                        ; Effectuer l'appel système
	mov r8, rax                    ; Stocker le nombre d'octets effectivement lus dans r8

	; Écrire les données sur la sortie standard
	mov rax, 1                     ; Appel système `write` (code 1)
	mov rdi, 1                     ; Sortie standard (descripteur 1)
	lea rsi, [buffer]              ; Adresse du buffer contenant les données à écrire
	mov rdx, r8                    ; Nombre d'octets à écrire (ceux lus précédemment)
	syscall                        ; Effectuer l'appel système

	; Fermer le fichier
	mov rax, 3                     ; Appel système `close` (code 3)
	mov rdi, [fd]                  ; Descripteur de fichier à fermer
	syscall                        ; Effectuer l'appel système

	; Terminer le programme
	mov rax, 60                    ; Appel système `exit` (code 60)
	xor rdi, rdi                   ; Code de retour 0 (succès)
	syscall                        ; Effectuer l'appel système
