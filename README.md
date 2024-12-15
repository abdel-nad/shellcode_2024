# Modification de fichiers ELF

Ce projet explore les techniques d'injection de code dans des fichiers binaires au format ELF sur Linux. L'objectif est de mieux comprendre la structure des exécutables et d'expérimenter des manipulations avancées.

## Présentation

Cet outil permet d'ajouter du code personnalisé à un fichier ELF tout en maintenant son fonctionnement initial.

### Fonctionnalités principales

- Injection de code dans un exécutable ELF
- Conservation des fonctionnalités originales du fichier modifié

## Instructions d'installation

Pour préparer l'environnement et compiler le projet, procédez comme suit :

1. Assemblez le code source avec :
```bash
nasm -f elf64 projet.s -o projet.o
```

2. Reliez le fichier assemblé pour créer l'exécutable :
```bash
ld projet.o -o projet
```

## Guide d'utilisation

### Étape 1 : Injection
Utilisez cette commande pour modifier un fichier ELF :
```bash
./projet fichier_a_infecter
```

#### Exemple
```bash
cp /bin/ls copie_ls  # Dupliquez ls pour réaliser un test sécurisé
./projet copie_ls
```

### Étape 2 : Test
Exécutez le fichier modifié pour observer les changements :
```bash
./copie_ls
```
Un comportement supplémentaire devrait intervenir avant que le programme ne s'exécute normalement.

## Notes techniques

- **Plateforme** : Linux uniquement (testé sur x86_64)
- **Format supporté** : ELF uniquement 

## Fonctionnement interne

L'outil repose sur les étapes suivantes :

1. Ajout d'une nouvelle section pour inclure le code personnalisé
2. Modification de l'adresse du point d'entrée pour exécuter cette section en premier
3. Retour à l'exécution du programme initial après l'exécution du code injecté


