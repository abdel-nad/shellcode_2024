#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <elf.h>

void print_error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file.elf>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *filename = argv[1];
    int fd = open(filename, O_RDWR);
    if (fd < 0) print_error("Failed to open file");

    // Obtenir la taille du fichier
    off_t file_size = lseek(fd, 0, SEEK_END);
    if (file_size == -1) print_error("Failed to get file size");

    // Mapper le fichier en mémoire
    uint8_t *elf_data = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (elf_data == MAP_FAILED) print_error("Failed to map file");

    // Vérifier l'en-tête ELF
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_data;
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 || ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr->e_ident[EI_MAG2] != ELFMAG2 || ehdr->e_ident[EI_MAG3] != ELFMAG3) {
        fprintf(stderr, "Not a valid ELF file\n");
        munmap(elf_data, file_size);
        close(fd);
        return EXIT_FAILURE;
    }

    // Parcourir la table des en-têtes de programme
    Elf64_Phdr *phdr = (Elf64_Phdr *)(elf_data + ehdr->e_phoff);
    int found = 0;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_NOTE) {
            printf("Found PT_NOTE at entry %d\n", i);

            // Convertir PT_NOTE en PT_LOAD
            phdr[i].p_type = PT_LOAD;
            phdr[i].p_flags = PF_R | PF_X; // Lecture et exécution
            phdr[i].p_vaddr = 0xc000000;  // Nouvelle adresse virtuelle
            phdr[i].p_filesz = 0;         // Exemple simplifié
            phdr[i].p_memsz = 0;          // Exemple simplifié
            phdr[i].p_align = 0x200000;   // Alignement typique
            found = 1;
            break;
        }
    }

    if (!found) {
        fprintf(stderr, "No PT_NOTE segment found\n");
    } else {
        printf("PT_NOTE segment successfully converted to PT_LOAD.\n");
    }

    // Synchroniser les modifications avec le fichier
    if (msync(elf_data, file_size, MS_SYNC) == -1) print_error("Failed to sync changes");

    // Nettoyer les ressources
    munmap(elf_data, file_size);
    close(fd);

    return EXIT_SUCCESS;
}

