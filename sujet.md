# Chiffrement de fichiers

Votre objectif est d'implémenter un utilitaire de chiffrement en ligne de
commande. Ce sujet comporte deux parties principales et une partie bonus.

## Partie 1 : Chiffrement d'un seul fichier

Pour commencer, vous allez implémenter le chiffrement et le déchiffrement d'un
seul fichier. Le fonctionnement du programme est le suivant.

L'utilisateur indique en ligne de commande :

- un fichier à chiffrer ou déchiffrer ;
- le nom du fichier de sortie.

Puis, il entre le mot de passe de manière _discrète_.

Vous devez ensuite dériver une clé symétrique pour le chiffrement.

Dans le cas du chiffrement, votre programme génère un fichier chiffré à partir
d'un fichier "clair".

Dans le cadre du déchiffrement, le programme échoue si le mot de passe est
erroné, et déchiffre le fichier en cas de réussite.

L'utilisation en chiffrement se fera de la manière suivante :

```bash
tool encrypt fichier_clair -o fichier_chiffre
```

Et en déchiffrement :

```bash
tool decrypt fichier_chiffre -o fichier_clair
```

### Note

Pour vous aider, vous pouvez (devrez) utiliser des **dépendances tierces**.
Nous vous conseillons les _crates_ suivantes :

- [rpassword](https://crates.io/crates/rpassword) pour la saisie du mot de passe ;
- [clap](https://crates.io/crates/clap) pour la gestion des arguments en ligne
  de commande ;
- [aes_gcm](https://crates.io/crates/aes_gcm) pour le chiffrement symétrique ;
- [argon2](https://crates.io/crates/argon2) pour la dérivation de la clé de
  chiffrement depuis le mot de passe utilisateur ;
- [rand](https://crates.io/crates/rand) pour la génération d'aléa.

## Partie 2 : Chiffrement de plusieurs fichiers

Selon le même principe, l'utilisateur peut choisir plusieurs fichiers à chiffrer :

```default
tool encrypt fichier_clair1 fichier_clair2 -o fichier_chiffre
```

Pour le déchiffrement, un dossier sera indiqué :

```default
tool decrypt fichier_chiffre -o repertoire
```

Dans ce cas, `repertoire` contiendra les deux fichiers clairs avec leur noms originels `fichier_clair1` et `fichier_clair2`.

## Bonus

- Aide en ligne pertinente ;
- Vérification de la qualité des mots de passe avant chiffrement ;
- Extensions asymétriques :
  - Seuls les destinataires peuvent ouvrir l'archive,
  - L'archive est signée par son émetteur.
