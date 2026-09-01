<p align="center">
  <img src="../../docs/assets/irontrace-banner.png" alt="IronTrace — Windows Hardware &amp; Forensic Integrity Scanner" width="100%">
</p>

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
  <strong>🌐 言語 / Languages</strong><br/>
  <a href="../../README.md">English</a> ·
  <a href="README.uk.md">Українська</a> ·
  <a href="README.de.md">Deutsch</a> ·
  <a href="README.fr.md">Français</a> ·
  <a href="README.es.md">Español</a> ·
  <a href="README.pl.md">Polski</a> ·
  <a href="README.pt.md">Português</a> ·
  <a href="README.zh-CN.md">中文</a> ·
  <b>日本語</b>
</p>

**ゲームサーバー管理者向けの Windows ハードウェア・フォレンジック整合性スキャナー。**

IronTrace は、プラットフォームのセキュリティ、PCI/PCIe/USB デバイス、ドライバー、およびオプションのフォレンジックシグナルに関する証拠を収集し、説明可能な整合性評価を生成します。マシンを**レビュー**するためのツールです。単一の異常な所見だけで誰かをチーターと断定することはありません。自動 BAN の経路もありません。

| チャネル | バージョン |
|---------|---------|
| アプリケーション | **0.7.0**（Phase 6 — Forensic Integrity Scan） |
| レポートスキーマ | `1.6` |
| API | `v1` |
| ドライバープロトコル | `2` |
| 参照 DB スキーマ | `2` |

---

## 目次

- [クイックスタート](#クイックスタート)
- [スキャンモード](#スキャンモード)
- [デスクトップアプリ（WPF）](#デスクトップアプリwpf)
- [CLI](#cli)
- [オプションのメモリスキャン（hollows_hunter）](#オプションのメモリスキャンhollows_hunter)
- [サーバーアップロードと管理者レビュー](#サーバーアップロードと管理者レビュー)
- [IronTrace の機能](#irontrace-の機能)
- [IronTrace でないもの](#irontrace-でないもの)
- [アーキテクチャ](#アーキテクチャ)
- [開発](#開発)
- [サードパーティに関する告知](#サードパーティに関する告知)
- [ロードマップ](#ロードマップ)
- [ドキュメント](#ドキュメント)
- [ライセンスと連絡先](#ライセンスと連絡先)

---

## クイックスタート

**エンドユーザー（公開ビルドまたは `dotnet run`）：**

1. Windows 10/11 x64 上で IronTrace を起動します。
2. ホーム画面でスキャンモードを選択します：
   - **Admin Scan** — サーバー管理者向けのハードウェアスキャン＋オプションのフォレンジック深度。
   - **Self-Audit** — プレイヤー向けスキャン。HTML レポートをデスクトップに自動保存します。
3. 結果画面で verdict と findings を確認します。
4. JSON をエクスポートするか、IronTrace サーバーにアップロードするか、新しいスキャンを開始します。

**開発者：**

```powershell
git clone <repo-url> dma-guard
cd dma-guard
dotnet restore IronTrace.sln
dotnet build IronTrace.sln -c Release
dotnet test IronTrace.sln -c Release
dotnet run --project src/IronTrace.App -c Release
```

`data/reference/` 配下にバンドルされた参照 DB がある場合、スキャンは**オフライン**で動作します。昇格は任意です（`asInvoker`）。Code Integrity / DeviceGuard の詳細が必要な場合のみ、管理者として実行してください。

---

## スキャンモード

IronTrace は**ハードウェアのみ**のスキャンと**フォレンジック**プロファイルを分離しています。フォレンジックレイヤーはプライバシーゲート付きです。メモリスキャンには明示的なオプトインと外部ツールが必要です（下記参照）。

| モード | WPF ボタン | CLI `--profile` | フォレンジックレイヤー | 典型的な用途 |
|------|------------|-----------------|-----------------|-------------|
| ハードウェアのみ | Admin Scan（フォレンジックチェックボックスなし） | `hardware-only` | なし | PCI/USB/ドライバーのベースライン整合性 |
| フルフォレンジック | Admin Scan ＋ プロセス/メモリチェックボックス | `full-forensic` | すべて（ツールインストール済み ＋ `--memory` でメモリ） | 管理者による詳細調査 |
| セルフ監査 | **Self-Audit** | `self-audit` | Execution、BYOVD、HWID、オーバーレイ、プロセスインベントリ | プレイヤー向け透明性レポート |
| コンソールリグ | — | `console-rig` | セルフ監査 ＋ キャプチャカード / 入力フォーカス | ストリーム構成のセカンダリ PC |

**フォレンジックレイヤー（Phase 6）：**

| レイヤー | 確認内容 | 同意 |
|-------|----------------|---------|
| 0 | Prefetch/BAM/ShimCache、BYOVD deep、HWID cross-source、オーバーレイ | Self-Audit / Full Forensic でオン |
| 1 | プロセス/サービスインベントリ、永続化（タスク、Run キー） | `IncludeProcessInventory` チェックボックスまたはプロファイル既定 |
| 2 | **hollows_hunter** サブプロセスによるメモリ整合性 | `IncludeMemoryScan` チェックボックスまたは CLI `--memory` |

hollows_hunter がインストールされていない場合、レイヤー 2 はスキップされます。それ以外はすべて実行されます。ツールが見つからない場合、UI に通知が表示されます。

---

## デスクトップアプリ（WPF）

```powershell
dotnet run --project src/IronTrace.App -c Release
```

### ホーム画面

| コントロール | 目的 |
|---------|---------|
| **Admin Scan** | ハードウェアスキャン。プロセスまたはメモリチェックボックスがオンだと Full Forensic になる |
| **Self-Audit** | フォレンジックセルフ監査プロファイル。`%USERPROFILE%\Desktop\` に HTML を保存 |
| Include process/service inventory | レイヤー 1 — 実行中のプロセスとサービスを一覧（プライバシーオプトイン） |
| Include memory scan via PE-sieve | レイヤー 2 — [hollows_hunter](#オプションのメモリスキャンhollows_hunter) がインストールされている場合のみ有効 |
| Include PnP device history | プライバシーオプトイン。過去の PCI エントリをウォッチリストと照合 |

### 結果画面

- **Verdict** — 保守的なリスクエンジン出力（`Normal` … `HighRisk`、自動 BAN なし）。
- **Forensic banner** — 該当する場合のフォレンジック概要。
- **Export report** — プライバシートグル付き JSON（デフォルトはシリアルハッシュ、生のシリアルではない）。
- **Upload to server** — チャレンジ/nonce ＋ HMAC で IronTrace インスタンスへ送信。
- **Browse devices / Findings** — PCI/USB と個別の findings へのドリルダウン。

---

## CLI

自動化、CI、管理者スクリプト向けのヘッドレススキャン：

```powershell
dotnet run --project src/IronTrace.Cli -c Release -- scan --profile self-audit --output report.json
```

```powershell
# Full forensic + memory (requires hollows_hunter in artifacts/tools/)
dotnet run --project src/IronTrace.Cli -c Release -- scan --profile full-forensic --memory --output report.json

# Hardware baseline only
dotnet run --project src/IronTrace.Cli -c Release -- scan --profile hardware-only --output report.json
```

| フラグ | 説明 |
|------|-------------|
| `--profile` | `hardware-only` · `full-forensic` · `self-audit` · `console-rig` |
| `--output` | JSON レポートパス（デフォルト：cwd 内のタイムスタンプ付きファイル） |
| `--html` | オプションの HTML パス（Self-Audit は JSON の隣に `.html` を自動生成） |
| `--memory` | レイヤー 2 メモリスキャンを有効化（full-forensic のみ） |

公開バイナリ名：`irontrace.exe`（`IronTrace.Cli` の publish から）。

---

## オプションのメモリスキャン（hollows_hunter）

IronTrace はメモリスキャンツールを**同梱しません**。オプトイン時、[hollows_hunter](https://github.com/hasherezade/hollows_hunter) を外部サブプロセスとして起動し、JSON stdout を解析します。プロセス内メモリ API は使用しません。レポートにメモリダンプも含まれません。

| コンポーネント | ライセンス | IronTrace に同梱？ |
|-----------|---------|-------------------------|
| [hollows_hunter](https://github.com/hasherezade/hollows_hunter) | BSD-2-Clause | **いいえ** |
| [pe-sieve](https://github.com/hasherezade/pe-sieve)（`pe-sieve64.dll`） | BSD-2-Clause | **いいえ** |

### インストール（初回のみ、管理者/ラボ）

1. アップストリームのリリースから 64 ビット Windows ビルドをダウンロードします。
2. リポジトリの開発用パスに配置します：

   ```text
   artifacts/tools/hollows_hunter64.exe
   artifacts/tools/pe-sieve64.dll
   ```

   公開アプリの場合は、実行ファイルの隣に `tools/` フォルダを使用します。

3. IronTrace を再起動します — ホーム画面の黄色の **"Memory scan tool not found"** バナーが消え、メモリチェックボックスが有効になります。

管理者バンドルで hollows_hunter/pe-sieve を再配布する場合、アップストリームの BSD-2-Clause 告知を保持してください。[THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md) および [docs/research/pe-sieve-hollows-hunter.md](../research/pe-sieve-hollows-hunter.md) を参照。

---

## サーバーアップロードと管理者レビュー

サーバーをローカルで起動：

```powershell
dotnet run --project src/IronTrace.Server -c Release
# → http://localhost:5188/admin
```

PostgreSQL 使用時：

```powershell
docker compose up -d
dotnet run --project src/IronTrace.Server -c Release
```

アップロードフロー：クライアントがチャレンジを要求 → HMAC でレポートに署名 → サーバーがスキャンを保存 → 管理者が `/admin` でトリアージ（Pending / Accepted / Rejected / NeedsInfo）。開発用ブートストラップ API キーと平文 HTTP はローカル作業専用です — 本番前にキーをローテーションし HTTPS を使用してください。詳細：[docs/api/README.md](../api/README.md)。

---

## IronTrace の機能

- OS ビルドとプラットフォームセキュリティを読み取り：Secure Boot、TPM、VBS、HVCI、Kernel DMA Protection、ハイパーバイザーフラグ
- マザーボード/BIOS 識別、PCI/PCIe デバイス、USB デバイスをインベントリ化
- オフライン `pci.ids` / `usb.ids` データベースからベンダー/デバイス名を解決
- ドライバーを一覧し、オフライン LOLDrivers スナップショットと照合（BYOVD 型の証拠、単独では verdict にならない）
- Code Integrity Operational ログのスナップショット（昇格時はより詳細）
- `IronTrace.Driver` によるオプションのカーネル PCI 証拠（ラボ test-signed。なしでも正常にデグレード）
- Safe challenge policy（デフォルト deny。デバイスリセットなし）および利用可能な caps での PCIe DOE 検出
- TBS 経由の best-effort Measured Boot PCR スナップショット（証拠のみ、証明ではない）
- 保守的なリスクエンジン → エクスポートプライバシートグル付きのバージョン付き JSON レポート（スキーマ 1.6）
- DMA ウォッチリスト、マルチシグナル `DMA_SIGNAL_CLUSTER`、オプションの PnP 履歴
- Phase 6 フォレンジック：実行アーティファクト、プロセスインベントリ、BYOVD deep、HWID cross-source、オーバーレイ/AI ビジョンシグナル
- 人的管理者レビュー用の IronTrace サーバーへのオプションアップロード

---

## IronTrace でないもの

- **暗号学的証明ではない。** ユーザーモードの PCI/USB ID は偽装可能。カーネル証拠は信頼度を上げるが、正直さを証明するものではない。[threat model](../security/THREAT_MODEL.md) を参照。
- **スパイウェアではない。** ブラウザ履歴、ドキュメント、パスワード、キー入力、スクリーンショット、任意のプロセスメモリダンプは収集しない。
- **DMA ツールキットではない。** オプションの KMDF ドライバーは限定的な PCI 証拠 IOCTL のみ実行（[driver boundary](../architecture/DRIVER_BOUNDARY.md)）。
- **チートツールの提供元ではない。** PCILeech、BYOVD エクスプロイトキット、HWID スプーファーは `docs/research/` 配下の調査用途のみ。

---

## アーキテクチャ

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

`IronTrace.Driver` は Visual Studio ＋ WDK でビルド（`dotnet` ではない）。CI はユーザーモードテストのみ実行。

**ソリューション構成：**

| パス | 役割 |
|------|------|
| `src/IronTrace.App` | WPF デスクトップクライアント |
| `src/IronTrace.Cli` | ヘッドレススキャナー |
| `src/IronTrace.Server` | アップロード API ＋ 管理 UI |
| `src/IronTrace.Core` | スキャンオーケストレーション |
| `src/IronTrace.Forensics` | Phase 6 コレクター |
| `src/IronTrace.Hardware` / `IronTrace.Windows` | プラットフォーム＆デバイスコレクター |
| `src/IronTrace.RiskEngine` | Findings と verdict |
| `data/reference/` | オフライン pci/usb/loldrivers DB |
| `artifacts/tools/` | オプション hollows_hunter（git 外） |

---

## 開発

### 要件

- Windows 10/11 x64
- [.NET 10 SDK](https://dotnet.microsoft.com/download)（`global.json` でバンドを固定）
- Docker（任意）— ローカルサーバースタック用 PostgreSQL
- Visual Studio ＋ WDK（任意）— `IronTrace.Driver` のみ

### ビルドとテスト

```powershell
dotnet restore IronTrace.sln
dotnet build IronTrace.sln -c Release
dotnet test IronTrace.sln -c Release
```

### 公開（self-contained win-x64）

```powershell
dotnet publish src/IronTrace.App -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o artifacts/publish/win-x64
```

self-contained 公開を使用する場合、エンドユーザーマシンに .NET ランタイムは不要です。

### 参照データベース

`data/reference/` 配下のバンドル DB により、ネットワークなしでスキャンが利用可能です。インポーターで再構築：

```powershell
dotnet run --project tools/HardwareDbImporter -- --mode pci --input path\to\pci.ids --output data/reference/pci-reference.db
dotnet run --project tools/HardwareDbImporter -- --mode usb --input path\to\usb.ids --output data/reference/usb-reference.db
dotnet run --project tools/HardwareDbImporter -- --mode loldrivers --input path\to\loldrivers --output data/reference/loldrivers-reference.db
```

署名付き参照更新パッケージ用の `gen-keys` / `sign-manifest` もサポート。[docs/database/REFERENCE_DB.md](../database/REFERENCE_DB.md) を参照。

### 設計ルール

- 告発より証拠 · unsupported は疑わしくない
- 未実装機能の偽の「success」なし
- JSON エクスポートはデフォルトでシリアル**ハッシュ**、生のシリアルではない
- サーバーアップロードは生のシリアルを送信しない。ユーザーが先に同意を確認
- アップロード API キーは平文設定より DPAPI 保存を優先
- 管理者レビューは人的トリアージのみ

完全なポリシー：[docs/security/PRIVACY.md](../security/PRIVACY.md)。

---

## サードパーティに関する告知

IronTrace は**オフライン参照データ**（pci.ids、usb.ids、LOLDrivers）を同梱 — [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md) を参照。

メモリスキャンツール（**hollows_hunter**、**pe-sieve**）は**サードパーティ、BSD-2-Clause、同梱なし** — レイヤー 2 メモリスキャンが必要な場合は別途インストールしてください。

---

## ロードマップ

| Phase | ステータス | 備考 |
|-------|--------|-------|
| 1 Foundation | Done (0.1.0) | WPF アプリ、PCI インベントリ、リスクエンジン、エクスポート |
| 2 Universal integrity | Done (0.2.0) | USB、ドライバー、LOLDrivers、CI ログ、署名付き ref 更新 |
| 3 Server challenge MVP | Done (0.3.0) | チャレンジアップロード、`/admin`、Docker Postgres |
| 4 Kernel evidence | Done (0.4.0) | KMDF ラボドライバー、プロトコル v2、レポートスキーマ 1.3 |
| 5 Active verification | Done (0.5.x) | Challenge policy、DOE/PCR、DMA triage/BAR/DSN |
| 6 Forensic integrity | Done (0.7.0) | Self-Audit、Full Forensic、オプション hollows_hunter |

バージョンチャネルは分離：アプリ、レポートスキーマ、API、参照 DB、ドライバープロトコル。[docs/architecture/PHASED_ROADMAP.md](../architecture/PHASED_ROADMAP.md) を参照。

---

## ドキュメント

| トピック | リンク |
|-------|------|
| Architecture | [docs/architecture/ARCHITECTURE.md](../architecture/ARCHITECTURE.md) |
| Phased roadmap | [docs/architecture/PHASED_ROADMAP.md](../architecture/PHASED_ROADMAP.md) |
| Driver boundary | [docs/architecture/DRIVER_BOUNDARY.md](../architecture/DRIVER_BOUNDARY.md) |
| Driver lab | [src/IronTrace.Driver/README.md](../../src/IronTrace.Driver/README.md) |
| API & upload | [docs/api/README.md](../api/README.md) |
| Threat model | [docs/security/THREAT_MODEL.md](../security/THREAT_MODEL.md) |
| Privacy | [docs/security/PRIVACY.md](../security/PRIVACY.md) |
| Reference DB | [docs/database/REFERENCE_DB.md](../database/REFERENCE_DB.md) |
| pe-sieve / hollows_hunter | [docs/research/pe-sieve-hollows-hunter.md](../research/pe-sieve-hollows-hunter.md) |
| Research index | [docs/research/README.md](../research/README.md) |
| Contributing | [CONTRIBUTING.md](../../CONTRIBUTING.md) |
| Security policy | [SECURITY.md](../../SECURITY.md) |

---

## ライセンスと連絡先

**IronTrace** — プロプライエタリ。[LICENSE](../../LICENSE) を参照。

**サードパーティデータとツール** — [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md)。

**Discord:** twinkipro

セキュリティ問題は非公開で報告してください（[SECURITY.md](../../SECURITY.md) 参照）。修正が整うまで、悪用可能なバグの公開 issue は開かないでください。
