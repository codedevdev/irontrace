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
  <strong>🌐 语言 / Languages</strong><br/>
  <a href="../../README.md">English</a> ·
  <a href="README.uk.md">Українська</a> ·
  <a href="README.de.md">Deutsch</a> ·
  <a href="README.fr.md">Français</a> ·
  <a href="README.es.md">Español</a> ·
  <a href="README.pl.md">Polski</a> ·
  <a href="README.pt.md">Português</a> ·
  <b>中文</b> ·
  <a href="README.ja.md">日本語</a>
</p>

**面向游戏服务器管理员的 Windows 硬件与取证完整性扫描器。**

IronTrace 收集平台安全、PCI/PCIe/USB 设备、驱动程序及可选取证信号的相关证据，并生成可解释的完整性评估。它帮助您**审查**一台机器，不会因单一异常发现就判定某人为作弊者，也没有自动封禁路径。

| 通道 | 版本 |
|------|------|
| 应用程序 | **0.7.0**（Phase 6 — Forensic Integrity Scan） |
| 报告 schema | `1.6` |
| API | `v1` |
| 驱动协议 | `2` |
| 参考 DB schema | `2` |

---

## 目录

- [快速开始](#快速开始)
- [扫描模式](#扫描模式)
- [桌面应用（WPF）](#桌面应用wpf)
- [CLI](#cli)
- [可选内存扫描（hollows_hunter）](#可选内存扫描hollows_hunter)
- [服务器上传与管理审查](#服务器上传与管理审查)
- [功能说明](#功能说明)
- [功能边界](#功能边界)
- [架构](#架构)
- [开发](#开发)
- [第三方声明](#第三方声明)
- [路线图](#路线图)
- [文档](#文档)
- [许可与联系](#许可与联系)

---

## 快速开始

**终端用户（已发布构建或 `dotnet run`）：**

1. 在 Windows 10/11 x64 上启动 IronTrace。
2. 在主页选择扫描模式：
   - **Admin Scan** — 面向服务器管理员的硬件扫描，可选取证深度。
   - **Self-Audit** — 面向玩家的扫描；自动将 HTML 报告保存到桌面。
3. 在结果页查看 verdict 与 findings。
4. 导出 JSON、上传到 IronTrace 服务器，或开始新扫描。

**开发者：**

```powershell
git clone <repo-url> dma-guard
cd dma-guard
dotnet restore IronTrace.sln
dotnet build IronTrace.sln -c Release
dotnet test IronTrace.sln -c Release
dotnet run --project src/IronTrace.App -c Release
```

当 `data/reference/` 下存在捆绑的参考 DB 时，扫描可**离线**运行。提升权限为可选项（`asInvoker`）；仅在需要更详细的 Code Integrity / DeviceGuard 信息时以管理员身份运行。

---

## 扫描模式

IronTrace 将**纯硬件**扫描与**取证**配置文件分开。取证层受隐私门控；内存扫描需明确选择并依赖外部工具（见下文）。

| 模式 | WPF 按钮 | CLI `--profile` | 取证层 | 典型用途 |
|------|----------|-----------------|--------|----------|
| 仅硬件 | Admin Scan（不勾选取证复选框） | `hardware-only` | 无 | PCI/USB/驱动基线 |
| 完整取证 | Admin Scan + 进程/内存复选框 | `full-forensic` | 全部（已安装工具且加 `--memory` 时含内存） | 深度管理调查 |
| 自检 | **Self-Audit** | `self-audit` | Execution、BYOVD、HWID、overlay、进程清单 | 玩家透明报告 |
| 主机 rig | — | `console-rig` | Self-Audit + 采集卡/输入焦点 | 直播场景中的副机 |

**取证层（Phase 6）：**

| 层 | 检查内容 | 授权 |
|----|----------|------|
| 0 | Prefetch/BAM/ShimCache、BYOVD deep、HWID cross-source、overlays | Self-Audit / Full Forensic 默认开启 |
| 1 | 进程/服务清单、持久化（任务、Run 键） | `IncludeProcessInventory` 复选框或配置文件默认 |
| 2 | 通过 **hollows_hunter** 子进程的内存完整性 | `IncludeMemoryScan` 复选框或 CLI `--memory` |

未安装 hollows_hunter 时跳过第 2 层，其余照常运行。工具缺失时 UI 会显示提示。

---

## 桌面应用（WPF）

```powershell
dotnet run --project src/IronTrace.App -c Release
```

### 主页

| 控件 | 用途 |
|------|------|
| **Admin Scan** | 硬件扫描；勾选进程或内存复选框时变为 Full Forensic |
| **Self-Audit** | 取证自检配置；将 HTML 保存到 `%USERPROFILE%\Desktop\` |
| Include process/service inventory | 第 1 层 — 列出运行中的进程与服务（隐私 opt-in） |
| Include memory scan via PE-sieve | 第 2 层 — 仅在已安装 [hollows_hunter](#可选内存扫描hollows_hunter) 时启用 |
| Include PnP device history | 隐私 opt-in；将历史 PCI 条目与 watchlist 关联 |

### 结果页

- **Verdict** — 保守风险引擎输出（`Normal` … `HighRisk`，永不自动封禁）。
- **Forensic banner** — 适用时的高层次取证摘要。
- **Export report** — 带隐私开关的 JSON（默认序列号哈希，非原始序列号）。
- **Upload to server** — 向 IronTrace 实例发起 challenge/nonce + HMAC。
- **Browse devices / Findings** — 深入查看 PCI/USB 与单项 findings。

---

## CLI

用于自动化、CI 或管理脚本的无界面扫描：

```powershell
dotnet run --project src/IronTrace.Cli -c Release -- scan --profile self-audit --output report.json
```

```powershell
# Full forensic + memory (requires hollows_hunter in artifacts/tools/)
dotnet run --project src/IronTrace.Cli -c Release -- scan --profile full-forensic --memory --output report.json

# Hardware baseline only
dotnet run --project src/IronTrace.Cli -c Release -- scan --profile hardware-only --output report.json
```

| 标志 | 说明 |
|------|------|
| `--profile` | `hardware-only` · `full-forensic` · `self-audit` · `console-rig` |
| `--output` | JSON 报告路径（默认：cwd 中带时间戳的文件） |
| `--html` | 可选 HTML 路径（Self-Audit 会在 JSON 旁自动生成 `.html`） |
| `--memory` | 启用第 2 层内存扫描（仅 full-forensic） |

发布二进制名称：`irontrace.exe`（来自 `IronTrace.Cli` publish）。

---

## 可选内存扫描（hollows_hunter）

IronTrace **不捆绑**内存扫描工具。选择启用时，以外部子进程启动 [hollows_hunter](https://github.com/hasherezade/hollows_hunter) 并解析 JSON stdout。无进程内内存 API；报告中不含内存转储。

| 组件 | 许可 | 随 IronTrace 分发？ |
|------|------|---------------------|
| [hollows_hunter](https://github.com/hasherezade/hollows_hunter) | BSD-2-Clause | **否** |
| [pe-sieve](https://github.com/hasherezade/pe-sieve)（`pe-sieve64.dll`） | BSD-2-Clause | **否** |

### 安装（一次性，管理员/实验室）

1. 从上游 release 下载 64 位 Windows 构建。
2. 放入仓库开发路径：

   ```text
   artifacts/tools/hollows_hunter64.exe
   artifacts/tools/pe-sieve64.dll
   ```

   已发布应用请在可执行文件旁使用 `tools/` 文件夹。

3. 重启 IronTrace — 主页黄色 **"Memory scan tool not found"** 横幅应消失，内存复选框变为可用。

若在管理 bundle 中再分发 hollows_hunter/pe-sieve，请保留上游 BSD-2-Clause 声明。见 [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md) 与 [docs/research/pe-sieve-hollows-hunter.md](../research/pe-sieve-hollows-hunter.md)。

---

## 服务器上传与管理审查

本地运行服务器：

```powershell
dotnet run --project src/IronTrace.Server -c Release
# → http://localhost:5188/admin
```

使用 PostgreSQL：

```powershell
docker compose up -d
dotnet run --project src/IronTrace.Server -c Release
```

上传流程：客户端请求 challenge → 用 HMAC 签名报告 → 服务器存储扫描 → 管理员在 `/admin` 中分诊（Pending / Accepted / Rejected / NeedsInfo）。开发用 bootstrap API 密钥与 plain HTTP 仅用于本地 — 生产前请轮换密钥并使用 HTTPS。详情：[docs/api/README.md](../api/README.md)。

---

## 功能说明

- 读取 OS 构建与平台安全：Secure Boot、TPM、VBS、HVCI、Kernel DMA Protection、hypervisor 标志
- 清点主板/BIOS 身份、PCI/PCIe 设备与 USB 设备
- 通过离线 `pci.ids` / `usb.ids` 数据库解析厂商/设备名称
- 列出驱动并与离线 LOLDrivers 快照匹配（BYOVD 类证据，本身不构成 verdict）
- 快照 Code Integrity Operational 日志（提升权限时细节更多）
- 可选通过 `IronTrace.Driver` 的内核 PCI 证据（实验室 test-signed；无驱动时优雅降级）
- Safe challenge policy（默认 deny；不重置设备）及在能力可用时的 PCIe DOE 检测
- 通过 TBS 尽力获取 Measured Boot PCR 快照（仅作证据，非 attestation）
- 保守风险引擎 → 带导出隐私开关的版本化 JSON 报告（schema 1.6）
- DMA watchlist、多信号 `DMA_SIGNAL_CLUSTER`、可选 PnP 历史
- Phase 6 取证：execution artifacts、进程清单、BYOVD deep、HWID cross-source、overlay/AI-vision 信号
- 可选上传到 IronTrace 服务器供人工管理审查

---

## 功能边界

- **非密码学证明。** 用户态 PCI/USB ID 可被伪造；内核证据提高置信度但不证明诚实。见 [threat model](../security/THREAT_MODEL.md)。
- **非间谍软件。** 不收集浏览器历史、文档、密码、按键、截图或任意进程内存转储。
- **非 DMA 工具包。** 可选 KMDF 驱动仅执行有界的 PCI 证据 IOCTL（[driver boundary](../architecture/DRIVER_BOUNDARY.md)）。
- **非作弊工具供应商。** PCILeech、BYOVD 利用套件与 HWID spoofer 仅在 `docs/research/` 下作研究用途。

---

## 架构

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

`IronTrace.Driver` 使用 Visual Studio + WDK 构建（非 `dotnet`）。CI 仅运行用户态测试。

**解决方案布局：**

| 路径 | 角色 |
|------|------|
| `src/IronTrace.App` | WPF 桌面客户端 |
| `src/IronTrace.Cli` | 无界面扫描器 |
| `src/IronTrace.Server` | 上传 API + 管理 UI |
| `src/IronTrace.Core` | 扫描编排 |
| `src/IronTrace.Forensics` | Phase 6 收集器 |
| `src/IronTrace.Hardware` / `IronTrace.Windows` | 平台与设备收集器 |
| `src/IronTrace.RiskEngine` | Findings 与 verdict |
| `data/reference/` | 离线 pci/usb/loldrivers DB |
| `artifacts/tools/` | 可选 hollows_hunter（不在 git 中） |

---

## 开发

### 环境要求

- Windows 10/11 x64
- [.NET 10 SDK](https://dotnet.microsoft.com/download)（`global.json` 固定版本带）
- Docker（可选）— 本地服务器栈的 PostgreSQL
- Visual Studio + WDK（可选）— 仅用于 `IronTrace.Driver`

### 构建与测试

```powershell
dotnet restore IronTrace.sln
dotnet build IronTrace.sln -c Release
dotnet test IronTrace.sln -c Release
```

### 发布（self-contained win-x64）

```powershell
dotnet publish src/IronTrace.App -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o artifacts/publish/win-x64
```

终端用户机器使用 self-contained 发布时无需 .NET 运行时。

### 参考数据库

`data/reference/` 下的捆绑 DB 使扫描在无网络时仍可用。使用导入器重建：

```powershell
dotnet run --project tools/HardwareDbImporter -- --mode pci --input path\to\pci.ids --output data/reference/pci-reference.db
dotnet run --project tools/HardwareDbImporter -- --mode usb --input path\to\usb.ids --output data/reference/usb-reference.db
dotnet run --project tools/HardwareDbImporter -- --mode loldrivers --input path\to\loldrivers --output data/reference/loldrivers-reference.db
```

另支持 `gen-keys` / `sign-manifest` 用于签名参考更新包。见 [docs/database/REFERENCE_DB.md](../database/REFERENCE_DB.md)。

### 设计原则

- 证据优于指控 · unsupported 不等于可疑
- 未实现功能不伪造「success」
- JSON 导出默认序列号**哈希**，非原始序列号
- 服务器上传永不发送原始序列号；用户先确认 consent
- 上传 API 密钥优先 DPAPI 存储而非明文配置
- 管理审查仅为人工分诊

完整策略：[docs/security/PRIVACY.md](../security/PRIVACY.md)。

---

## 第三方声明

IronTrace 附带**离线参考数据**（pci.ids、usb.ids、LOLDrivers）— 见 [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md)。

内存扫描工具（**hollows_hunter**、**pe-sieve**）为**第三方、BSD-2-Clause、不捆绑** — 若需第 2 层内存扫描请单独安装。

---

## 路线图

| 阶段 | 状态 | 说明 |
|------|------|------|
| 1 Foundation | Done (0.1.0) | WPF 应用、PCI 清单、风险引擎、导出 |
| 2 Universal integrity | Done (0.2.0) | USB、驱动、LOLDrivers、CI 日志、签名 ref 更新 |
| 3 Server challenge MVP | Done (0.3.0) | Challenge 上传、`/admin`、Docker Postgres |
| 4 Kernel evidence | Done (0.4.0) | KMDF 实验室驱动、协议 v2、报告 schema 1.3 |
| 5 Active verification | Done (0.5.x) | Challenge policy、DOE/PCR、DMA triage/BAR/DSN |
| 6 Forensic integrity | Done (0.7.0) | Self-Audit、Full Forensic、可选 hollows_hunter |

版本通道相互独立：应用、报告 schema、API、参考 DB、驱动协议。见 [docs/architecture/PHASED_ROADMAP.md](../architecture/PHASED_ROADMAP.md)。

---

## 文档

| 主题 | 链接 |
|------|------|
| 架构 | [docs/architecture/ARCHITECTURE.md](../architecture/ARCHITECTURE.md) |
| 分阶段路线图 | [docs/architecture/PHASED_ROADMAP.md](../architecture/PHASED_ROADMAP.md) |
| 驱动边界 | [docs/architecture/DRIVER_BOUNDARY.md](../architecture/DRIVER_BOUNDARY.md) |
| 驱动实验室 | [src/IronTrace.Driver/README.md](../../src/IronTrace.Driver/README.md) |
| API 与上传 | [docs/api/README.md](../api/README.md) |
| 威胁模型 | [docs/security/THREAT_MODEL.md](../security/THREAT_MODEL.md) |
| 隐私 | [docs/security/PRIVACY.md](../security/PRIVACY.md) |
| 参考 DB | [docs/database/REFERENCE_DB.md](../database/REFERENCE_DB.md) |
| pe-sieve / hollows_hunter | [docs/research/pe-sieve-hollows-hunter.md](../research/pe-sieve-hollows-hunter.md) |
| 研究索引 | [docs/research/README.md](../research/README.md) |
| 贡献指南 | [CONTRIBUTING.md](../../CONTRIBUTING.md) |
| 安全策略 | [SECURITY.md](../../SECURITY.md) |

---

## 许可与联系

**IronTrace** — 专有软件。见 [LICENSE](../../LICENSE)。

**第三方数据与工具** — [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md)。

**Discord：** twinkipro

安全问题请私下报告（见 [SECURITY.md](../../SECURITY.md)）。在修复就绪前请勿为可利用漏洞公开开 issue。
