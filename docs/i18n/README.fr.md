# IronTrace

<p align="center">
  <a href="https://github.com/codedevdev/irontrace/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/codedevdev/irontrace/actions/workflows/ci.yml/badge.svg?branch=main"></a>
  <a href="https://github.com/codedevdev/irontrace/actions/workflows/release.yml"><img alt="Release" src="https://github.com/codedevdev/irontrace/actions/workflows/release.yml/badge.svg?branch=main"></a>
  <a href="https://github.com/codedevdev/irontrace/releases/latest"><img alt="Latest Release" src="https://img.shields.io/github/v/release/codedevdev/irontrace?label=release"></a>
  <a href="https://github.com/codedevdev/irontrace/releases"><img alt="Downloads" src="https://img.shields.io/github/downloads/codedevdev/irontrace/total?label=downloads"></a>
  <a href="https://dotnet.microsoft.com/"><img alt=".NET 10" src="https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet"></a>
  <a href="https://github.com/codedevdev/irontrace"><img alt="Platform" src="https://img.shields.io/badge/platform-Windows%20x64-0078D4?logo=windows"></a>
  <a href="../../LICENSE"><img alt="License" src="https://img.shields.io/github/license/codedevdev/irontrace"></a>
</p>

<p align="center">
  <strong>🌐 Langues / Languages</strong><br/>
  <a href="../../README.md">English</a> ·
  <a href="README.uk.md">Українська</a> ·
  <a href="README.de.md">Deutsch</a> ·
  <b>Français</b> ·
  <a href="README.es.md">Español</a> ·
  <a href="README.pl.md">Polski</a> ·
  <a href="README.pt.md">Português</a> ·
  <a href="README.zh-CN.md">中文</a> ·
  <a href="README.ja.md">日本語</a>
</p>

**Scanner Windows d'intégrité matérielle et forensique pour les administrateurs de serveurs de jeu.**

IronTrace collecte des preuves sur la sécurité de la plateforme, les périphériques PCI/PCIe/USB, les pilotes et des signaux forensiques optionnels — puis produit une évaluation d'intégrité explicable. Il vous aide à **examiner** une machine. Il ne déclare pas quelqu'un tricheur sur la base d'une seule anomalie. Il n'existe aucun chemin d'auto-ban.

| Canal | Version |
|-------|---------|
| Application | **0.7.0** (Phase 6 — Forensic Integrity Scan) |
| Schéma de rapport | `1.6` |
| API | `v1` |
| Protocole pilote | `2` |
| Schéma de la base de référence | `2` |

---

## Table des matières

- [Démarrage rapide](#démarrage-rapide)
- [Modes de scan](#modes-de-scan)
- [Application bureau (WPF)](#application-bureau-wpf)
- [CLI](#cli)
- [Scan mémoire optionnel (hollows_hunter)](#scan-mémoire-optionnel-hollows_hunter)
- [Envoi au serveur et revue admin](#envoi-au-serveur-et-revue-admin)
- [Ce qu'il fait](#ce-quil-fait)
- [Ce qu'il n'est pas](#ce-quil-nest-pas)
- [Architecture](#architecture)
- [Développement](#développement)
- [Avis tiers](#avis-tiers)
- [Documentation](#documentation)
- [Licence et contact](#licence-et-contact)

---

## Démarrage rapide

**Utilisateur final (build publié ou `dotnet run`) :**

1. Lancez IronTrace sur Windows 10/11 x64.
2. Choisissez un mode de scan sur l'écran d'accueil :
   - **Admin Scan** — matériel + profondeur forensique optionnelle pour les admins serveur.
   - **Self-Audit** — scan orienté joueur ; enregistre automatiquement le rapport HTML sur le Bureau.
3. Consultez le verdict et les constatations sur l'écran Result.
4. Exportez en JSON, envoyez vers votre serveur IronTrace ou lancez un nouveau scan.

**Développeur :**

```powershell
git clone <repo-url> dma-guard
cd dma-guard
dotnet restore IronTrace.sln
dotnet build IronTrace.sln -c Release
dotnet test IronTrace.sln -c Release
dotnet run --project src/IronTrace.App -c Release
```

Les scans fonctionnent **hors ligne** lorsque les bases de référence sous `data/reference/` sont présentes. L'élévation est optionnelle (`asInvoker`) ; exécutez en tant qu'Administrateur uniquement si vous souhaitez plus de détails Code Integrity / DeviceGuard.

---

## Modes de scan

IronTrace sépare les scans **matériel uniquement** des profils **forensiques**. Les couches forensiques sont soumises au consentement ; le scan mémoire nécessite un opt-in explicite et des outils externes (voir ci-dessous).

| Mode | Bouton WPF | CLI `--profile` | Couches forensiques | Usage typique |
|------|------------|-----------------|---------------------|---------------|
| Matériel uniquement | Admin Scan (sans cases forensiques) | `hardware-only` | Aucune | Intégrité PCI/USB/pilotes de base |
| Forensique complet | Admin Scan + cases processus / mémoire | `full-forensic` | Toutes (mémoire si outil installé + `--memory`) | Investigation admin approfondie |
| Self-audit | **Self-Audit** | `self-audit` | Execution, BYOVD, HWID, overlay, inventaire processus | Rapport de transparence joueur |
| Console rig | — | `console-rig` | Self-audit + carte de capture / focus entrée | PC secondaire dans un setup stream |

**Couches forensiques (Phase 6) :**

| Couche | Ce qu'elle vérifie | Consentement |
|--------|-------------------|--------------|
| 0 | Prefetch/BAM/ShimCache, BYOVD deep, HWID multi-sources, overlays | Activé pour Self-Audit / Full Forensic |
| 1 | Inventaire processus/services, persistance (tâches, clés Run) | Case `IncludeProcessInventory` ou profil par défaut |
| 2 | Intégrité mémoire via sous-processus **hollows_hunter** | Case `IncludeMemoryScan` ou CLI `--memory` |

Sans hollows_hunter installé, la couche 2 est ignorée — tout le reste s'exécute. L'interface affiche un avertissement lorsque l'outil est absent.

---

## Application bureau (WPF)

```powershell
dotnet run --project src/IronTrace.App -c Release
```

### Écran d'accueil

| Contrôle | Rôle |
|----------|------|
| **Admin Scan** | Scan matériel ; devient Full Forensic si les cases processus ou mémoire sont cochées |
| **Self-Audit** | Profil forensique self-audit ; enregistre le HTML dans `%USERPROFILE%\Desktop\` |
| Include process/service inventory | Couche 1 — liste les processus et services en cours (opt-in confidentialité) |
| Include memory scan via PE-sieve | Couche 2 — activé uniquement si [hollows_hunter](#scan-mémoire-optionnel-hollows_hunter) est installé |
| Include PnP device history | Opt-in confidentialité ; corrèle l'historique PCI avec la watchlist |

### Écran Result

- **Verdict** — sortie du moteur de risque conservateur (`Normal` … `HighRisk`, jamais d'auto-ban).
- **Bannière forensique** — résumé forensique de haut niveau le cas échéant.
- **Export report** — JSON avec options de confidentialité (hash de numéro de série par défaut, pas le numéro brut).
- **Upload to server** — challenge/nonce + HMAC vers votre instance IronTrace.
- **Browse devices / Findings** — détail PCI/USB et constatations individuelles.

---

## CLI

Scans sans interface pour l'automatisation, la CI ou les scripts admin :

```powershell
dotnet run --project src/IronTrace.Cli -c Release -- scan --profile self-audit --output report.json
```

```powershell
# Full forensic + memory (requires hollows_hunter in artifacts/tools/)
dotnet run --project src/IronTrace.Cli -c Release -- scan --profile full-forensic --memory --output report.json

# Hardware baseline only
dotnet run --project src/IronTrace.Cli -c Release -- scan --profile hardware-only --output report.json
```

| Option | Description |
|--------|-------------|
| `--profile` | `hardware-only` · `full-forensic` · `self-audit` · `console-rig` |
| `--output` | Chemin du rapport JSON (par défaut : fichier horodaté dans le répertoire courant) |
| `--html` | Chemin HTML optionnel (Self-Audit génère automatiquement un `.html` à côté du JSON) |
| `--memory` | Active le scan mémoire couche 2 (full-forensic uniquement) |

Nom du binaire publié : `irontrace.exe` (publish depuis `IronTrace.Cli`).

---

## Scan mémoire optionnel (hollows_hunter)

IronTrace **n'inclut pas** d'outils de scan mémoire. Lorsqu'il est activé, il lance [hollows_hunter](https://github.com/hasherezade/hollows_hunter) comme sous-processus externe et analyse la sortie JSON stdout. Pas d'API mémoire in-process ; pas de dumps mémoire dans les rapports.

| Composant | Licence | Inclus avec IronTrace ? |
|-----------|---------|-------------------------|
| [hollows_hunter](https://github.com/hasherezade/hollows_hunter) | BSD-2-Clause | **Non** |
| [pe-sieve](https://github.com/hasherezade/pe-sieve) (`pe-sieve64.dll`) | BSD-2-Clause | **Non** |

### Installation (une fois, admin/lab)

1. Téléchargez les builds Windows 64 bits depuis les releases upstream.
2. Placez les fichiers dans le chemin de dev du dépôt :

   ```text
   artifacts/tools/hollows_hunter64.exe
   artifacts/tools/pe-sieve64.dll
   ```

   Pour une application publiée, utilisez un dossier `tools/` à côté de l'exécutable.

3. Redémarrez IronTrace — la bannière jaune **« Memory scan tool not found »** sur l'accueil doit disparaître et la case mémoire devient activable.

Si vous redistribuez hollows_hunter/pe-sieve dans votre bundle admin, conservez les avis BSD-2-Clause upstream. Voir [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md) et [docs/research/pe-sieve-hollows-hunter.md](../research/pe-sieve-hollows-hunter.md).

---

## Envoi au serveur et revue admin

Lancez le serveur en local :

```powershell
dotnet run --project src/IronTrace.Server -c Release
# → http://localhost:5188/admin
```

Avec PostgreSQL :

```powershell
docker compose up -d
dotnet run --project src/IronTrace.Server -c Release
```

Flux d'envoi : le client demande un challenge → signe le rapport avec HMAC → le serveur stocke le scan → l'admin trie dans `/admin` (Pending / Accepted / Rejected / NeedsInfo). Les clés API de bootstrap dev et le HTTP en clair sont réservés au travail local — faites tourner les clés et utilisez HTTPS avant la production. Détails : [docs/api/README.md](../api/README.md).

---

## Ce qu'il fait

- Lit la build OS et la sécurité plateforme : Secure Boot, TPM, VBS, HVCI, Kernel DMA Protection, drapeaux hyperviseur
- Inventorie l'identité carte mère/BIOS, les périphériques PCI/PCIe et USB
- Résout les noms fabricant/périphérique depuis les bases hors ligne `pci.ids` / `usb.ids`
- Liste les pilotes et les compare à un instantané LOLDrivers hors ligne (preuve de type BYOVD, pas un verdict en soi)
- Capture le journal opérationnel Code Integrity (plus de détails en élévation)
- Preuve PCI noyau optionnelle via `IronTrace.Driver` (test-signé lab ; dégradation propre sans lui)
- Politique de challenge sûre (refus par défaut ; pas de reset périphérique) et détection PCIe DOE lorsque les capacités sont disponibles
- Instantané PCR Measured Boot via TBS au mieux (preuve uniquement, pas d'attestation)
- Moteur de risque conservateur → rapport JSON versionné (schéma 1.6) avec options d'export confidentialité
- Watchlist DMA, cluster multi-signaux `DMA_SIGNAL_CLUSTER`, historique PnP optionnel
- Forensique Phase 6 : artefacts d'exécution, inventaire processus, BYOVD deep, HWID multi-sources, signaux overlay/vision IA
- Envoi optionnel vers votre serveur IronTrace pour revue humaine par un admin

---

## Ce qu'il n'est pas

- **Pas une preuve cryptographique.** Les ID PCI/USB en mode utilisateur peuvent être falsifiés ; la preuve noyau augmente la confiance mais ne prouve pas l'honnêteté. Voir le [modèle de menace](../security/THREAT_MODEL.md).
- **Pas un logiciel espion.** Pas d'historique navigateur, documents, mots de passe, frappes clavier, captures d'écran ni dumps mémoire arbitraires de processus.
- **Pas une boîte à outils DMA.** Le pilote KMDF optionnel n'exécute que des IOCTL PCI bornés ([limite pilote](../architecture/DRIVER_BOUNDARY.md)).
- **Pas un fournisseur d'outils de triche.** PCILeech, kits d'exploit BYOVD et spoofers HWID sont recherche uniquement sous `docs/research/`.

---

## Architecture

```text
WPF / CLI
  → Windows + Hardware collectors
  → optional KernelEvidence / MeasuredBoot
  → optional Forensic pipeline (Phase 6)
  → SafeChallengePolicy + DoeSpdmDetector
  → local reference DBs (pci.ids, usb.ids, LOLDrivers)
  → RiskEngine → JSON report (schema 1.6)
  → optional Upload (challenge + HMAC) → Server /admin
```

`IronTrace.Driver` est compilé avec Visual Studio + WDK (pas `dotnet`). La CI exécute uniquement les tests en mode utilisateur.

**Organisation de la solution :**

| Chemin | Rôle |
|--------|------|
| `src/IronTrace.App` | Client bureau WPF |
| `src/IronTrace.Cli` | Scanner headless |
| `src/IronTrace.Server` | API d'envoi + interface admin |
| `src/IronTrace.Core` | Orchestration des scans |
| `src/IronTrace.Forensics` | Collecteurs Phase 6 |
| `src/IronTrace.Hardware` / `IronTrace.Windows` | Collecteurs plateforme et périphériques |
| `src/IronTrace.RiskEngine` | Constatations et verdict |
| `data/reference/` | Bases hors ligne pci/usb/loldrivers |
| `artifacts/tools/` | hollows_hunter optionnel (pas dans git) |

---

## Développement

### Prérequis

- Windows 10/11 x64
- [.NET 10 SDK](https://dotnet.microsoft.com/download) (`global.json` fixe la bande)
- Docker (optionnel) — PostgreSQL pour la stack serveur locale
- Visual Studio + WDK (optionnel) — uniquement pour `IronTrace.Driver`

### Build et tests

```powershell
dotnet restore IronTrace.sln
dotnet build IronTrace.sln -c Release
dotnet test IronTrace.sln -c Release
```

### Publication (self-contained win-x64)

```powershell
dotnet publish src/IronTrace.App -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o artifacts/publish/win-x64
```

Les machines utilisateur finales n'ont pas besoin du runtime .NET avec une publication self-contained.

### Base de référence

Les bases incluses sous `data/reference/` permettent des scans sans réseau. Reconstruisez avec l'importateur :

```powershell
dotnet run --project tools/HardwareDbImporter -- --mode pci --input path\to\pci.ids --output data/reference/pci-reference.db
dotnet run --project tools/HardwareDbImporter -- --mode usb --input path\to\usb.ids --output data/reference/usb-reference.db
dotnet run --project tools/HardwareDbImporter -- --mode loldrivers --input path\to\loldrivers --output data/reference/loldrivers-reference.db
```

Prend aussi en charge `gen-keys` / `sign-manifest` pour les paquets de mise à jour de référence signés. Voir [docs/database/REFERENCE_DB.md](../database/REFERENCE_DB.md).

### Règles de conception

- Preuves plutôt qu'accusations · non pris en charge n'est pas suspect
- Pas de faux « succès » pour des fonctionnalités non implémentées
- L'export JSON utilise par défaut le **hash** du numéro de série, pas le numéro brut
- L'envoi serveur n'envoie jamais le numéro de série brut ; l'utilisateur confirme son consentement d'abord
- Les clés API d'envoi préfèrent le stockage DPAPI au config en clair
- La revue admin est un triage humain uniquement

Politique complète : [docs/security/PRIVACY.md](../security/PRIVACY.md).

---

## Avis tiers

IronTrace inclut des **données de référence hors ligne** (pci.ids, usb.ids, LOLDrivers) — voir [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md).

Les outils de scan mémoire (**hollows_hunter**, **pe-sieve**) sont **tiers, BSD-2-Clause, non inclus** — installez-les séparément si vous voulez le scan mémoire couche 2.

---

## Feuille de route

| Phase | Statut | Notes |
|-------|--------|-------|
| 1 Foundation | Terminé (0.1.0) | App WPF, inventaire PCI, moteur de risque, export |
| 2 Universal integrity | Terminé (0.2.0) | USB, pilotes, LOLDrivers, journaux CI, mises à jour ref signées |
| 3 Server challenge MVP | Terminé (0.3.0) | Envoi challenge, `/admin`, Docker Postgres |
| 4 Kernel evidence | Terminé (0.4.0) | Pilote KMDF lab, protocole v2, schéma rapport 1.3 |
| 5 Active verification | Terminé (0.5.x) | Politique challenge, DOE/PCR, triage DMA/BAR/DSN |
| 6 Forensic integrity | Terminé (0.7.0) | Self-Audit, Full Forensic, hollows_hunter optionnel |

Les canaux de version restent séparés : application, schéma de rapport, API, base de référence, protocole pilote. Voir [docs/architecture/PHASED_ROADMAP.md](../architecture/PHASED_ROADMAP.md).

---

## Documentation

| Sujet | Lien |
|-------|------|
| Architecture | [docs/architecture/ARCHITECTURE.md](../architecture/ARCHITECTURE.md) |
| Feuille de route par phases | [docs/architecture/PHASED_ROADMAP.md](../architecture/PHASED_ROADMAP.md) |
| Limite pilote | [docs/architecture/DRIVER_BOUNDARY.md](../architecture/DRIVER_BOUNDARY.md) |
| Lab pilote | [src/IronTrace.Driver/README.md](../../src/IronTrace.Driver/README.md) |
| API et envoi | [docs/api/README.md](../api/README.md) |
| Modèle de menace | [docs/security/THREAT_MODEL.md](../security/THREAT_MODEL.md) |
| Confidentialité | [docs/security/PRIVACY.md](../security/PRIVACY.md) |
| Base de référence | [docs/database/REFERENCE_DB.md](../database/REFERENCE_DB.md) |
| pe-sieve / hollows_hunter | [docs/research/pe-sieve-hollows-hunter.md](../research/pe-sieve-hollows-hunter.md) |
| Index recherche | [docs/research/README.md](../research/README.md) |
| Contribution | [CONTRIBUTING.md](../../CONTRIBUTING.md) |
| Politique de sécurité | [SECURITY.md](../../SECURITY.md) |

---

## Licence et contact

**IronTrace** — propriétaire. Voir [LICENSE](../../LICENSE).

**Données et outils tiers** — [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md).

**Discord :** twinkipro

Pour les problèmes de sécurité, signalez en privé (voir [SECURITY.md](../../SECURITY.md)). N'ouvrez pas d'issues publiques pour des failles exploitables avant qu'un correctif soit prêt.
