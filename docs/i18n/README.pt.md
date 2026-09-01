# IronTrace

<p align="center">
  <strong>🌐 Idiomas / Languages</strong><br/>
  <a href="../../README.md">English</a> ·
  <a href="README.uk.md">Українська</a> ·
  <a href="README.de.md">Deutsch</a> ·
  <a href="README.fr.md">Français</a> ·
  <a href="README.es.md">Español</a> ·
  <a href="README.pl.md">Polski</a> ·
  <b>Português</b> ·
  <a href="README.zh-CN.md">中文</a> ·
  <a href="README.ja.md">日本語</a>
</p>

**Scanner de integridade de hardware e forense para Windows, voltado a administradores de servidores de jogos.**

IronTrace coleta evidências sobre segurança da plataforma, dispositivos PCI/PCIe/USB, drivers e sinais forenses opcionais — e produz uma avaliação de integridade explicável. Ele ajuda você a **revisar** uma máquina. Não declara ninguém como trapaceiro por um único achado incomum. Não há caminho de banimento automático.

| Canal | Versão |
|-------|--------|
| Aplicativo | **0.7.0** (Fase 6 — Forensic Integrity Scan) |
| Esquema de relatório | `1.6` |
| API | `v1` |
| Protocolo do driver | `2` |
| Esquema do banco de referência | `2` |

---

## Índice

- [Início rápido](#início-rápido)
- [Modos de varredura](#modos-de-varredura)
- [Aplicativo desktop (WPF)](#aplicativo-desktop-wpf)
- [CLI](#cli)
- [Varredura de memória opcional (hollows_hunter)](#varredura-de-memória-opcional-hollows_hunter)
- [Envio ao servidor e revisão administrativa](#envio-ao-servidor-e-revisão-administrativa)
- [O que faz](#o-que-faz)
- [O que não é](#o-que-não-é)
- [Arquitetura](#arquitetura)
- [Desenvolvimento](#desenvolvimento)
- [Avisos de terceiros](#avisos-de-terceiros)
- [Documentação](#documentação)
- [Licença e contato](#licença-e-contato)

---

## Início rápido

**Usuário final (build publicado ou `dotnet run`):**

1. Inicie o IronTrace no Windows 10/11 x64.
2. Escolha um modo de varredura na tela inicial:
   - **Admin Scan** — hardware + profundidade forense opcional para admins de servidor.
   - **Self-Audit** — varredura voltada ao jogador; salva automaticamente o relatório HTML na Área de Trabalho.
3. Revise o veredito e os achados na tela de Resultado.
4. Exporte JSON, envie para o seu servidor IronTrace ou inicie uma nova varredura.

**Desenvolvedor:**

```powershell
git clone <repo-url> dma-guard
cd dma-guard
dotnet restore IronTrace.sln
dotnet build IronTrace.sln -c Release
dotnet test IronTrace.sln -c Release
dotnet run --project src/IronTrace.App -c Release
```

As varreduras funcionam **offline** quando os bancos de referência em `data/reference/` estão presentes. Elevação é opcional (`asInvoker`); execute como Administrador apenas se quiser mais detalhes de Code Integrity / DeviceGuard.

---

## Modos de varredura

O IronTrace separa varreduras **somente de hardware** de perfis **forenses**. As camadas forenses são protegidas por privacidade; a varredura de memória exige opt-in explícito e ferramentas externas (veja abaixo).

| Modo | Botão WPF | CLI `--profile` | Camadas forenses | Uso típico |
|------|-----------|-----------------|------------------|------------|
| Somente hardware | Admin Scan (sem checkboxes forenses) | `hardware-only` | Nenhuma | Linha de base PCI/USB/driver |
| Forense completo | Admin Scan + checkboxes de processo / memória | `full-forensic` | Todas (memória se a ferramenta estiver instalada + `--memory`) | Investigação profunda por admin |
| Self-audit | **Self-Audit** | `self-audit` | Execution, BYOVD, HWID, overlay, process inventory | Relatório de transparência para jogadores |
| Console rig | — | `console-rig` | Self-audit + placa de captura / foco em input | PC secundário em setup de stream |

**Camadas forenses (Fase 6):**

| Camada | O que verifica | Consentimento |
|--------|----------------|---------------|
| 0 | Prefetch/BAM/ShimCache, BYOVD deep, HWID cross-source, overlays | Ativo em Self-Audit / Full Forensic |
| 1 | Inventário de processos/serviços, persistência (tasks, Run keys) | Checkbox `IncludeProcessInventory` ou padrão do perfil |
| 2 | Integridade de memória via subprocesso **hollows_hunter** | Checkbox `IncludeMemoryScan` ou CLI `--memory` |

Sem o hollows_hunter instalado, a Camada 2 é ignorada — todo o resto continua executando. A UI exibe um aviso quando a ferramenta está ausente.

---

## Aplicativo desktop (WPF)

```powershell
dotnet run --project src/IronTrace.App -c Release
```

### Tela inicial

| Controle | Finalidade |
|----------|------------|
| **Admin Scan** | Varredura de hardware; vira Full Forensic se checkboxes de processo ou memória estiverem marcados |
| **Self-Audit** | Perfil forense self-audit; salva HTML em `%USERPROFILE%\Desktop\` |
| Include process/service inventory | Camada 1 — lista processos e serviços em execução (opt-in de privacidade) |
| Include memory scan via PE-sieve | Camada 2 — habilitado apenas quando [hollows_hunter](#varredura-de-memória-opcional-hollows_hunter) está instalado |
| Include PnP device history | Opt-in de privacidade; correlaciona entradas PCI históricas com a watchlist |

### Tela de resultado

- **Verdict** — saída conservadora do motor de risco (`Normal` … `HighRisk`, nunca banimento automático).
- **Forensic banner** — resumo forense de alto nível, quando aplicável.
- **Export report** — JSON com toggles de privacidade (hash de serial por padrão, não serial bruto).
- **Upload to server** — challenge/nonce + HMAC para a sua instância IronTrace.
- **Browse devices / Findings** — detalhamento de PCI/USB e achados individuais.

---

## CLI

Varreduras headless para automação, CI ou scripts de admin:

```powershell
dotnet run --project src/IronTrace.Cli -c Release -- scan --profile self-audit --output report.json
```

```powershell
# Full forensic + memory (requires hollows_hunter in artifacts/tools/)
dotnet run --project src/IronTrace.Cli -c Release -- scan --profile full-forensic --memory --output report.json

# Hardware baseline only
dotnet run --project src/IronTrace.Cli -c Release -- scan --profile hardware-only --output report.json
```

| Flag | Descrição |
|------|-----------|
| `--profile` | `hardware-only` · `full-forensic` · `self-audit` · `console-rig` |
| `--output` | Caminho do relatório JSON (padrão: arquivo com timestamp no cwd) |
| `--html` | Caminho HTML opcional (Self-Audit gera `.html` ao lado do JSON) |
| `--memory` | Habilita varredura de memória Camada 2 (apenas full-forensic) |

Nome do binário publicado: `irontrace.exe` (via publish do `IronTrace.Cli`).

---

## Varredura de memória opcional (hollows_hunter)

O IronTrace **não inclui** ferramentas de varredura de memória. Quando habilitado, ele inicia o [hollows_hunter](https://github.com/hasherezade/hollows_hunter) como subprocesso externo e analisa o stdout JSON. Sem APIs de memória in-process; sem dumps de memória nos relatórios.

| Componente | Licença | Incluído no IronTrace? |
|------------|---------|------------------------|
| [hollows_hunter](https://github.com/hasherezade/hollows_hunter) | BSD-2-Clause | **Não** |
| [pe-sieve](https://github.com/hasherezade/pe-sieve) (`pe-sieve64.dll`) | BSD-2-Clause | **Não** |

### Instalação (única vez, admin/lab)

1. Baixe builds Windows 64-bit dos releases upstream.
2. Coloque os arquivos no caminho de desenvolvimento do repositório:

   ```text
   artifacts/tools/hollows_hunter64.exe
   artifacts/tools/pe-sieve64.dll
   ```

   Para um app publicado, use uma pasta `tools/` ao lado do executável.

3. Reinicie o IronTrace — o banner amarelo **"Memory scan tool not found"** na tela inicial deve desaparecer e o checkbox de memória fica habilitado.

Se você redistribuir hollows_hunter/pe-sieve no seu pacote de admin, mantenha os avisos upstream BSD-2-Clause. Veja [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md) e [docs/research/pe-sieve-hollows-hunter.md](../research/pe-sieve-hollows-hunter.md).

---

## Envio ao servidor e revisão administrativa

Execute o servidor localmente:

```powershell
dotnet run --project src/IronTrace.Server -c Release
# → http://localhost:5188/admin
```

Com PostgreSQL:

```powershell
docker compose up -d
dotnet run --project src/IronTrace.Server -c Release
```

Fluxo de envio: o cliente solicita challenge → assina o relatório com HMAC → o servidor armazena a varredura → o admin faz triagem em `/admin` (Pending / Accepted / Rejected / NeedsInfo). Chaves de API de bootstrap de dev e HTTP simples são apenas para trabalho local — rotacione as chaves e use HTTPS antes de produção. Detalhes: [docs/api/README.md](../api/README.md).

---

## O que faz

- Lê build do SO e segurança da plataforma: Secure Boot, TPM, VBS, HVCI, Kernel DMA Protection, flags de hypervisor
- Inventaria identidade de placa-mãe/BIOS, dispositivos PCI/PCIe e dispositivos USB
- Resolve nomes de vendor/device a partir de bancos offline `pci.ids` / `usb.ids`
- Lista drivers e compara com snapshot offline LOLDrivers (evidência estilo BYOVD, não um veredito por si só)
- Snapshot do log operacional Code Integrity (mais detalhes quando elevado)
- Evidência PCI no kernel opcional via `IronTrace.Driver` (test-signed de lab; degrada graciosamente sem ele)
- Política de challenge segura (deny por padrão; sem reset de dispositivo) e detecção PCIe DOE onde caps estão disponíveis
- Snapshot PCR Measured Boot best-effort via TBS (apenas evidência, não attestation)
- Motor de risco conservador → relatório JSON versionado (schema 1.6) com toggles de privacidade na exportação
- Watchlist DMA, `DMA_SIGNAL_CLUSTER` multi-sinal, histórico PnP opcional
- Forense Fase 6: artefatos de execução, inventário de processos, BYOVD deep, HWID cross-source, sinais overlay/AI-vision
- Envio opcional para o seu servidor IronTrace para revisão humana por admin

---

## O que não é

- **Não é prova criptográfica.** IDs PCI/USB em user-mode podem ser falsificados; evidência no kernel aumenta a confiança, mas não prova honestidade. Veja [threat model](../security/THREAT_MODEL.md).
- **Não é spyware.** Sem histórico de navegador, documentos, senhas, teclas digitadas, capturas de tela ou dumps arbitrários de memória de processos.
- **Não é um toolkit DMA.** O driver KMDF opcional executa apenas IOCTLs limitados de evidência PCI ([driver boundary](../architecture/DRIVER_BOUNDARY.md)).
- **Não é fornecedor de ferramentas de cheat.** PCILeech, kits de exploit BYOVD e spoofers de HWID são apenas para pesquisa em `docs/research/`.

---

## Arquitetura

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

O `IronTrace.Driver` é compilado com Visual Studio + WDK (não com `dotnet`). O CI executa apenas testes em user-mode.

**Layout da solution:**

| Caminho | Função |
|---------|--------|
| `src/IronTrace.App` | Cliente desktop WPF |
| `src/IronTrace.Cli` | Scanner headless |
| `src/IronTrace.Server` | API de upload + UI admin |
| `src/IronTrace.Core` | Orquestração de varredura |
| `src/IronTrace.Forensics` | Collectors Fase 6 |
| `src/IronTrace.Hardware` / `IronTrace.Windows` | Collectors de plataforma e dispositivos |
| `src/IronTrace.RiskEngine` | Achados e veredito |
| `data/reference/` | DBs offline pci/usb/loldrivers |
| `artifacts/tools/` | hollows_hunter opcional (não está no git) |

---

## Desenvolvimento

### Requisitos

- Windows 10/11 x64
- [.NET 10 SDK](https://dotnet.microsoft.com/download) (`global.json` fixa a faixa)
- Docker (opcional) — PostgreSQL para stack local do servidor
- Visual Studio + WDK (opcional) — apenas para `IronTrace.Driver`

### Build e testes

```powershell
dotnet restore IronTrace.sln
dotnet build IronTrace.sln -c Release
dotnet test IronTrace.sln -c Release
```

### Publish (self-contained win-x64)

```powershell
dotnet publish src/IronTrace.App -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o artifacts/publish/win-x64
```

Máquinas de usuário final não precisam do runtime .NET ao usar publish self-contained.

### Banco de referência

DBs incluídos em `data/reference/` mantêm varreduras utilizáveis sem rede. Reconstrua com o importador:

```powershell
dotnet run --project tools/HardwareDbImporter -- --mode pci --input path\to\pci.ids --output data/reference/pci-reference.db
dotnet run --project tools/HardwareDbImporter -- --mode usb --input path\to\usb.ids --output data/reference/usb-reference.db
dotnet run --project tools/HardwareDbImporter -- --mode loldrivers --input path\to\loldrivers --output data/reference/loldrivers-reference.db
```

Também suporta `gen-keys` / `sign-manifest` para pacotes de atualização de referência assinados. Veja [docs/database/REFERENCE_DB.md](../database/REFERENCE_DB.md).

### Regras de design

- Evidência em vez de acusações · unsupported não é suspeito
- Sem "success" falso para recursos não implementados
- Exportação JSON usa **hash** de serial por padrão, não serial bruto
- Envio ao servidor nunca envia serial bruto; o usuário confirma consentimento primeiro
- Chaves de API de upload preferem armazenamento DPAPI em vez de config em texto plano
- Revisão admin é apenas triagem humana

Política completa: [docs/security/PRIVACY.md](../security/PRIVACY.md).

---

## Avisos de terceiros

O IronTrace inclui **dados de referência offline** (pci.ids, usb.ids, LOLDrivers) — veja [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md).

Ferramentas de varredura de memória (**hollows_hunter**, **pe-sieve**) são **de terceiros, BSD-2-Clause, não incluídas** — instale-as separadamente se quiser a varredura de memória Camada 2.

---

## Roadmap

| Fase | Status | Notas |
|------|--------|-------|
| 1 Foundation | Done (0.1.0) | App WPF, inventário PCI, motor de risco, exportação |
| 2 Universal integrity | Done (0.2.0) | USB, drivers, LOLDrivers, logs CI, atualizações de ref assinadas |
| 3 Server challenge MVP | Done (0.3.0) | Upload com challenge, `/admin`, Docker Postgres |
| 4 Kernel evidence | Done (0.4.0) | Driver KMDF de lab, protocolo v2, schema de relatório 1.3 |
| 5 Active verification | Done (0.5.x) | Política de challenge, DOE/PCR, triagem DMA/BAR/DSN |
| 6 Forensic integrity | Done (0.7.0) | Self-Audit, Full Forensic, hollows_hunter opcional |

Canais de versão permanecem separados: app, schema de relatório, API, banco de referência, protocolo do driver. Veja [docs/architecture/PHASED_ROADMAP.md](../architecture/PHASED_ROADMAP.md).

---

## Documentação

| Tópico | Link |
|--------|------|
| Arquitetura | [docs/architecture/ARCHITECTURE.md](../architecture/ARCHITECTURE.md) |
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

## Licença e contato

**IronTrace** — proprietário. Veja [LICENSE](../../LICENSE).

**Dados e ferramentas de terceiros** — [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md).

**Discord:** twinkipro

Para problemas de segurança, reporte em privado (veja [SECURITY.md](../../SECURITY.md)). Não abra issues públicas para bugs exploráveis até que uma correção esteja pronta.
