# Spécifications --- Projet de synchronisation chiffrée

## Vision

Créer une plateforme de synchronisation temps réel, orientée CLI et GUI,
avec chiffrement de bout en bout, déduplication, compression adaptative
et hautes performances.

## Objectifs

-   Synchronisation quasi temps réel.
-   Chiffrement E2EE.
-   Déduplication par chunks.
-   Versioning.
-   Fonctionnement hors ligne puis reprise.
-   Multi-plateforme (Linux, macOS, Windows).

## Architecture

-   Client Rust (CLI + GUI).
-   Moteur de synchronisation.
-   Watchers natifs (inotify/FSEvents/ReadDirectoryChangesW).
-   Pipeline :
    1.  Détection.
    2.  Chunking (FastCDC).
    3.  Hash (BLAKE3).
    4.  Compression (Zstd adaptatif).
    5.  Chiffrement (XChaCha20-Poly1305).
    6.  Upload via QUIC/HTTP3.

## Sécurité

-   Argon2id pour la dérivation des clés.
-   HKDF pour les sous-clés.
-   Clé différente par fichier et par chunk.
-   Métadonnées chiffrées.
-   Vérification d'intégrité par BLAKE3.

## Modèle de menace

-   Serveur distant honnête mais curieux.
-   Attaquant réseau actif ou passif.
-   Le serveur ne doit jamais voir le contenu en clair.
-   Les noms de fichiers, chemins et métadonnées sensibles doivent être
    chiffrés autant que possible.
-   La compromission d'un appareil client reste hors du périmètre E2EE et doit
    être traitée comme un incident local.

## Gestion des clés et des appareils

-   Une clé maîtresse utilisateur est dérivée via Argon2id.
-   HKDF dérive des sous-clés par appareil, fichier et chunk.
-   Chaque appareil doit disposer d'un identifiant unique et d'un statut
    d'autorisation.
-   L'ajout d'un nouvel appareil doit nécessiter une validation explicite
    depuis un appareil déjà autorisé ou via une clé de récupération.
-   Prévoir rotation, révocation et perte d'appareil.
-   Le mot de passe ne doit jamais quitter la machine cliente.
-   MVP : une identité cryptographique locale peut être dérivée au login puis
    conservée localement dans la session cliente pour permettre upload, pull et
    partage en CLI.
-   Chaque utilisateur publie une clé publique au serveur afin de permettre le
    partage E2EE sans exposer les clés de fichier en clair.

## Réponse à compromission

-   Prévoir un mode panic ou nuke intégré.
-   L'utilisateur autorisé doit pouvoir envoyer une commande signée au serveur
    pour déclencher l'effacement distant des objets chiffrés, manifestes et
    métadonnées associées au workspace.
-   Un appareil client peut déclencher un auto-wipe local en cas d'événement
    critique détecté ou d'ordre distant authentifié.
-   Le wipe local doit supprimer les clés en priorité, puis la base SQLite, le
    cache, les manifestes locaux et la file d'attente.
-   Le wipe distant doit être journalisé et propagé à tous les appareils connus.
-   Toute commande de destruction doit exiger une authentification forte, une
    signature cryptographique et idéalement une double confirmation.
-   Prévoir un délai de grâce optionnel pour annuler une destruction lancée par
    erreur.
-   La suppression sécurisée des fichiers locaux reste best effort selon le
    système de fichiers et l'OS ; la suppression des clés doit être considérée
    comme la mesure principale.
-   Déclencheurs possibles :
    1.  demande manuelle de l'utilisateur
    2.  trop grand nombre d'échecs d'authentification
    3.  appareil révoqué tentant encore d'accéder aux données
    4.  détection d'intégrité incohérente ou d'environnement compromis

## Base locale

-   SQLite.
-   Index des fichiers.
-   Mapping chunks.
-   Historique local.
-   File d'attente des opérations.
-   Journal persistant pour reprise après crash.

## Stockage distant

Stockage objet compatible S3. Le serveur ne connaît que les objets
chiffrés.

## Authentification et contrôle d'accès

-   Le serveur doit supporter `register` et `login` en ligne de commande.
-   Chaque fichier ou objet logique appartient à un utilisateur propriétaire.
-   Un utilisateur ne peut voir ou manipuler que ses propres fichiers, sauf si
    un autre utilisateur lui partage explicitement un accès.
-   Le partage doit être explicite, traçable et révocable.
-   Le contrôle d'accès côté serveur s'applique au minimum sur les métadonnées,
    les manifestes et les autorisations d'accès.
-   Le chiffrement E2EE reste géré côté client ; le serveur applique les droits
    mais ne doit pas connaître le contenu en clair.

## API serveur MVP

-   `POST /register`
-   `POST /login`
-   `POST /upload`
-   `POST /share`
-   `POST /unshare`
-   `POST /delete`
-   `GET /files`
-   `GET /download`
-   Authentification par jeton de session signé ou opaque.
-   Le serveur stocke des blobs chiffrés opaques ; le chiffrement et le
    déchiffrement des contenus ont lieu uniquement côté client.
-   Déploiement possible sur un hôte distant via SSH, avec préférence pour des
    clés SSH plutôt qu'un mot de passe interactif.

## Flux E2EE MVP

-   À la connexion, le client dérive localement une identité cryptographique
    via Argon2id à partir du secret utilisateur.
-   À chaque upload, le client génère une clé de fichier aléatoire.
-   Le contenu est chiffré côté client via XChaCha20-Poly1305 avec cette clé
    de fichier.
-   La clé de fichier est encapsulée pour le propriétaire via sa clé publique.
-   Lors d'un partage, le propriétaire récupère la clé de fichier puis
    l'encapsule pour le destinataire via sa clé publique.
-   HKDF dérive les clés de wrapping à partir du secret partagé et du chemin
    logique distant.
-   Le serveur ne manipule que des blobs chiffrés opaques et des clés de
    fichier encapsulées.
-   Au pull, le client télécharge le blob et la clé encapsulée qui lui
    correspond, puis déchiffre localement le contenu.

## Modèle de données

-   Workspace.
-   Device.
-   FileEntry.
-   FileVersion.
-   ChunkRef.
-   Manifest chiffré.
-   SyncCursor.
-   PendingOp.

## Sémantique de synchronisation

-   Le protocole logique doit rester indépendant du transport.
-   Les opérations doivent être idempotentes.
-   Le client doit pouvoir reprendre une synchronisation interrompue sans
    ré-uploader les objets déjà validés.
-   Le fonctionnement hors ligne repose sur un journal local puis un replay.
-   Le système doit distinguer création, modification, suppression, renommage
    et déplacement.
-   Le scan initial et le watch temps réel doivent produire le même modèle
    d'événements internes.
-   Le MVP peut propager les suppressions via replay d'opérations locales, même
    avant l'arrivée d'un historique complet.

## Conflits

-   Deux modifications concurrentes ne doivent jamais provoquer de perte
    silencieuse de données.
-   En cas de conflit, conserver plusieurs versions plutôt qu'écraser.
-   Cas à gérer explicitement :
    1.  modification / modification
    2.  suppression / modification
    3.  renommage / modification
    4.  déplacement / modification
-   La résolution manuelle peut être suffisante pour le MVP.

## Rétention et garbage collection

-   Une suppression crée d'abord un tombstone versionné.
-   Les anciennes versions suivent une politique de rétention configurable.
-   Un chunk ne peut être supprimé du stockage distant que s'il n'est plus
    référencé par aucun manifeste actif.
-   La garbage collection doit être différée, sûre et relançable.

## Reprise et robustesse

-   Toute opération locale ou distante doit être journalisée avant exécution.
-   Après crash, la reprise doit recharger l'état depuis SQLite puis rejouer la
    file d'attente.
-   Chaque étape critique doit être vérifiée par hash et taille attendue.
-   Les uploads et downloads doivent supporter reprise, retry et backoff.
-   Les écritures locales doivent être atomiques autant que possible.

## Contraintes de performance

-   Optimiser en priorité le cas des petits changements fréquents.
-   Limiter l'utilisation mémoire pendant le chunking de gros fichiers.
-   Prévoir un comportement stable sur de très grandes arborescences.
-   La compression adaptative doit pouvoir être désactivée si elle n'apporte
    pas de gain réel.
-   La déduplication doit rester compatible avec le chiffrement de bout en bout.

## CLI

-   sync init
-   sync register
-   sync login
-   sync watch
-   sync watch --sync
-   sync push
-   sync upload
-   sync pull
-   sync list
-   sync share
-   sync unshare
-   sync delete
-   sync status
-   sync diff
-   sync history
-   sync restore
-   sync nuke

## Roadmap

### MVP

-   Watcher
-   Watch avec upload auto des creations/modifications
-   Chunking
-   Upload
-   Download
-   Chiffrement
-   CLI
-   Register / login
-   Upload CLI
-   Contrôle d'accès propriétaire
-   Reprise après crash
-   Gestion minimale des conflits
-   Journal local SQLite

### v1

-   GUI
-   Historique
-   Partage
-   Gestion des conflits
-   Gestion multi-appareils
-   Rétention configurable
-   Panic mode / auto-wipe

### v2

-   Synchronisation P2P
-   Montage comme disque virtuel
-   Compression adaptative avancée
-   Delta binaire

## Tests

-   Tests de corruption locale.
-   Tests de perte réseau et reprise.
-   Tests de conflit multi-appareils.
-   Tests de gros fichiers.
-   Tests de grandes arborescences.
-   Tests de crash pendant upload, download et restauration.
-   Tests de compatibilité Linux, macOS et Windows.

## Priorités techniques

1.  Robustesse
2.  Sécurité
3.  Performances
4.  Simplicité de maintenance
