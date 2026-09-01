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
  <strong>🌐 Idiomas / Languages</strong><br/>
  <a href="../../README.md">English</a> ·
  <a href="README.uk.md">Українська</a> ·
  <a href="README.de.md">Deutsch</a> ·
  <a href="README.fr.md">Français</a> ·
  <b>Español</b> ·
  <a href="README.pl.md">Polski</a> ·
  <a href="README.pt.md">Português</a> ·
  <a href="README.zh-CN.md">中文</a> ·
  <a href="README.ja.md">日本語</a>
</p>

**Escáner de integridad de hardware y forense de Windows para administradores de servidores de juegos.**

IronTrace recopila evidencia sobre la seguridad de la plataforma, dispositivos PCI/PCIe/USB, controladores y señales forenses opcionales — y produce una evaluación de integridad explicable. Le ayuda a **revisar** una máquina. No declara a alguien tramposo por un solo hallazgo inusual. No hay ruta de auto-baneo.

| Canal | Versión |
|-------|---------|
| Aplicación | **0.7.0** (Fase 6 — Forensic Integrity Scan) |
| Esquema de informe | `1.6` |
| API | `v1` |
| Protocolo del controlador | `2` |
| Esquema de BD de referencia | `2` |

---

## Tabla de contenidos

- [Inicio rápido](#inicio-rápido)
- [Modos de escaneo](#modos-de-escaneo)
- [Aplicación de escritorio (WPF)](#aplicación-de-escritorio-wpf)
- [CLI](#cli)
- [Escaneo de memoria opcional (hollows_hunter)](#escaneo-de-memoria-opcional-hollows_hunter)
- [Carga al servidor y revisión administrativa](#carga-al-servidor-y-revisión-administrativa)
- [Qué hace](#qué-hace)
- [Qué no es](#qué-no-es)
- [Arquitectura](#arquitectura)
- [Desarrollo](#desarrollo)
- [Avisos de terceros](#avisos-de-terceros)
- [Documentación](#documentación)
- [Licencia y contacto](#licencia-y-contacto)

---

## Inicio rápido

**Usuario final (compilación publicada o `dotnet run`):**

1. Inicie IronTrace en Windows 10/11 x64.
2. Elija un modo de escaneo en la pantalla de inicio:
   - **Admin Scan** — hardware + profundidad forense opcional para administradores de servidor.
   - **Self-Audit** — escaneo orientado al jugador; guarda automáticamente el informe HTML en el Escritorio.
3. Revise el veredicto y los hallazgos en la pantalla Result.
4. Exporte JSON, cargue a su servidor IronTrace o inicie un nuevo escaneo.

**Desarrollador:**

```powershell
git clone <repo-url> dma-guard
cd dma-guard
dotnet restore IronTrace.sln
dotnet build IronTrace.sln -c Release
dotnet test IronTrace.sln -c Release
dotnet run --project src/IronTrace.App -c Release
```

Los escaneos funcionan **sin conexión** cuando las BD de referencia incluidas en `data/reference/` están presentes. La elevación es opcional (`asInvoker`); ejecute como Administrador solo si desea más detalle de Code Integrity / DeviceGuard.

---

## Modos de escaneo

IronTrace separa los escaneos **solo de hardware** de los perfiles **forenses**. Las capas forenses están sujetas a privacidad; el escaneo de memoria requiere opt-in explícito y herramientas externas (véase más abajo).

| Modo | Botón WPF | CLI `--profile` | Capas forenses | Uso típico |
|------|-----------|-----------------|----------------|------------|
| Solo hardware | Admin Scan (sin casillas forenses) | `hardware-only` | Ninguna | Integridad base PCI/USB/controladores |
| Forense completo | Admin Scan + casillas de proceso / memoria | `full-forensic` | Todas (memoria si la herramienta está instalada + `--memory`) | Investigación administrativa profunda |
| Auto-auditoría | **Self-Audit** | `self-audit` | Execution, BYOVD, HWID, overlay, inventario de procesos | Informe de transparencia para el jugador |
| Console rig | — | `console-rig` | Self-audit + tarjeta de captura / foco de entrada | PC secundario en una configuración de streaming |

**Capas forenses (Fase 6):**

| Capa | Qué comprueba | Consentimiento |
|------|---------------|----------------|
| 0 | Prefetch/BAM/ShimCache, BYOVD deep, HWID cross-source, overlays | Activado en Self-Audit / Full Forensic |
| 1 | Inventario de procesos/servicios, persistencia (tareas, claves Run) | Casilla `IncludeProcessInventory` o valor predeterminado del perfil |
| 2 | Integridad de memoria vía subproceso **hollows_hunter** | Casilla `IncludeMemoryScan` o CLI `--memory` |

Sin hollows_hunter instalado, la Capa 2 se omite — todo lo demás sigue ejecutándose. La interfaz muestra un aviso cuando falta la herramienta.

---

## Aplicación de escritorio (WPF)

```powershell
dotnet run --project src/IronTrace.App -c Release
```

### Pantalla de inicio

| Control | Propósito |
|---------|-----------|
| **Admin Scan** | Escaneo de hardware; pasa a Full Forensic si se marcan las casillas de proceso o memoria |
| **Self-Audit** | Perfil forense de auto-auditoría; guarda HTML en `%USERPROFILE%\Desktop\` |
| Include process/service inventory | Capa 1 — lista procesos y servicios en ejecución (opt-in de privacidad) |
| Include memory scan via PE-sieve | Capa 2 — solo habilitado cuando [hollows_hunter](#escaneo-de-memoria-opcional-hollows_hunter) está instalado |
| Include PnP device history | Opt-in de privacidad; correlaciona entradas PCI históricas con la lista de vigilancia |

### Pantalla Result

- **Verdict** — salida del motor de riesgo conservador (`Normal` … `HighRisk`, nunca auto-baneo).
- **Forensic banner** — resumen forense de alto nivel cuando corresponda.
- **Export report** — JSON con opciones de privacidad (hash de serie por defecto, no serie en bruto).
- **Upload to server** — challenge/nonce + HMAC a su instancia IronTrace.
- **Browse devices / Findings** — detalle de PCI/USB y hallazgos individuales.

---

## CLI

Escaneos sin interfaz para automatización, CI o scripts de administración:

```powershell
dotnet run --project src/IronTrace.Cli -c Release -- scan --profile self-audit --output report.json
```

```powershell
# Full forensic + memory (requires hollows_hunter in artifacts/tools/)
dotnet run --project src/IronTrace.Cli -c Release -- scan --profile full-forensic --memory --output report.json

# Hardware baseline only
dotnet run --project src/IronTrace.Cli -c Release -- scan --profile hardware-only --output report.json
```

| Flag | Descripción |
|------|-------------|
| `--profile` | `hardware-only` · `full-forensic` · `self-audit` · `console-rig` |
| `--output` | Ruta del informe JSON (predeterminado: archivo con marca de tiempo en cwd) |
| `--html` | Ruta HTML opcional (Self-Audit genera `.html` junto al JSON) |
| `--memory` | Habilitar escaneo de memoria Capa 2 (solo full-forensic) |

Nombre del binario publicado: `irontrace.exe` (desde la publicación de `IronTrace.Cli`).

---

## Escaneo de memoria opcional (hollows_hunter)

IronTrace **no incluye** herramientas de escaneo de memoria. Cuando se opta por ello, lanza [hollows_hunter](https://github.com/hasherezade/hollows_hunter) como subproceso externo y analiza la salida JSON de stdout. Sin APIs de memoria en proceso; sin volcados de memoria en los informes.

| Componente | Licencia | ¿Incluido con IronTrace? |
|------------|----------|--------------------------|
| [hollows_hunter](https://github.com/hasherezade/hollows_hunter) | BSD-2-Clause | **No** |
| [pe-sieve](https://github.com/hasherezade/pe-sieve) (`pe-sieve64.dll`) | BSD-2-Clause | **No** |

### Instalación (una vez, admin/laboratorio)

1. Descargue compilaciones de Windows de 64 bits desde los releases upstream.
2. Coloque los archivos en la ruta de desarrollo del repositorio:

   ```text
   artifacts/tools/hollows_hunter64.exe
   artifacts/tools/pe-sieve64.dll
   ```

   Para una aplicación publicada, use una carpeta `tools/` junto al ejecutable.

3. Reinicie IronTrace — el banner amarillo **"Memory scan tool not found"** en Home debería desaparecer y la casilla de memoria quedará habilitada.

Si redistribuye hollows_hunter/pe-sieve en su paquete de administración, conserve los avisos BSD-2-Clause upstream. Véase [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md) y [docs/research/pe-sieve-hollows-hunter.md](../research/pe-sieve-hollows-hunter.md).

---

## Carga al servidor y revisión administrativa

Ejecute el servidor localmente:

```powershell
dotnet run --project src/IronTrace.Server -c Release
# → http://localhost:5188/admin
```

Con PostgreSQL:

```powershell
docker compose up -d
dotnet run --project src/IronTrace.Server -c Release
```

Flujo de carga: el cliente solicita challenge → firma el informe con HMAC → el servidor almacena el escaneo → el administrador hace triage en `/admin` (Pending / Accepted / Rejected / NeedsInfo). Las claves API de bootstrap de desarrollo y HTTP sin cifrar son solo para trabajo local — rote las claves y use HTTPS antes de producción. Detalles: [docs/api/README.md](../api/README.md).

---

## Qué hace

- Lee la compilación del SO y la seguridad de la plataforma: Secure Boot, TPM, VBS, HVCI, Kernel DMA Protection, flags de hipervisor
- Inventaría identidad de placa base/BIOS, dispositivos PCI/PCIe y dispositivos USB
- Resuelve nombres de fabricante/dispositivo desde BD offline `pci.ids` / `usb.ids`
- Lista controladores y los compara con la instantánea offline de LOLDrivers (evidencia estilo BYOVD, no un veredicto por sí sola)
- Captura el registro operativo Code Integrity (más detalle con privilegios elevados)
- Evidencia PCI en kernel opcional vía `IronTrace.Driver` (firmado de prueba de laboratorio; se degrada limpiamente sin él)
- Política de challenge segura (denegación por defecto; sin reinicio de dispositivo) y detección PCIe DOE donde las capacidades estén disponibles
- Instantánea PCR de Measured Boot vía TBS (solo evidencia, no atestación)
- Motor de riesgo conservador → informe JSON versionado (esquema 1.6) con opciones de privacidad en la exportación
- Lista de vigilancia DMA, `DMA_SIGNAL_CLUSTER` multi-señal, historial PnP opcional
- Forense Fase 6: artefactos de ejecución, inventario de procesos, BYOVD deep, HWID cross-source, señales overlay/AI-vision
- Carga opcional a su servidor IronTrace para revisión humana por administradores

---

## Qué no es

- **No es prueba criptográfica.** Los ID PCI/USB en modo usuario pueden falsificarse; la evidencia en kernel aumenta la confianza pero no demuestra honestidad. Véase [modelo de amenazas](../security/THREAT_MODEL.md).
- **No es spyware.** Sin historial del navegador, documentos, contraseñas, pulsaciones de teclas, capturas de pantalla ni volcados arbitrarios de memoria de procesos.
- **No es un kit de herramientas DMA.** El controlador KMDF opcional realiza solo IOCTLs PCI de evidencia acotados ([límite del controlador](../architecture/DRIVER_BOUNDARY.md)).
- **No es un proveedor de herramientas de trampas.** PCILeech, kits de explotación BYOVD y spoofers HWID son solo de investigación bajo `docs/research/`.

---

## Arquitectura

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

`IronTrace.Driver` se compila con Visual Studio + WDK (no con `dotnet`). CI ejecuta solo pruebas en modo usuario.

**Estructura de la solución:**

| Ruta | Rol |
|------|-----|
| `src/IronTrace.App` | Cliente de escritorio WPF |
| `src/IronTrace.Cli` | Escáner sin interfaz |
| `src/IronTrace.Server` | API de carga + interfaz de administración |
| `src/IronTrace.Core` | Orquestación de escaneos |
| `src/IronTrace.Forensics` | Recolectores Fase 6 |
| `src/IronTrace.Hardware` / `IronTrace.Windows` | Recolectores de plataforma y dispositivos |
| `src/IronTrace.RiskEngine` | Hallazgos y veredicto |
| `data/reference/` | BD offline pci/usb/loldrivers |
| `artifacts/tools/` | hollows_hunter opcional (no en git) |

---

## Desarrollo

### Requisitos

- Windows 10/11 x64
- [.NET 10 SDK](https://dotnet.microsoft.com/download) (`global.json` fija la banda)
- Docker (opcional) — PostgreSQL para la pila de servidor local
- Visual Studio + WDK (opcional) — solo para `IronTrace.Driver`

### Compilación y pruebas

```powershell
dotnet restore IronTrace.sln
dotnet build IronTrace.sln -c Release
dotnet test IronTrace.sln -c Release
```

### Publicación (autocontenido win-x64)

```powershell
dotnet publish src/IronTrace.App -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o artifacts/publish/win-x64
```

Las máquinas de usuario final no necesitan el runtime de .NET al usar una publicación autocontenida.

### Base de datos de referencia

Las BD incluidas en `data/reference/` mantienen los escaneos utilizables sin red. Reconstruya con el importador:

```powershell
dotnet run --project tools/HardwareDbImporter -- --mode pci --input path\to\pci.ids --output data/reference/pci-reference.db
dotnet run --project tools/HardwareDbImporter -- --mode usb --input path\to\usb.ids --output data/reference/usb-reference.db
dotnet run --project tools/HardwareDbImporter -- --mode loldrivers --input path\to\loldrivers --output data/reference/loldrivers-reference.db
```

También admite `gen-keys` / `sign-manifest` para paquetes de actualización de referencia firmados. Véase [docs/database/REFERENCE_DB.md](../database/REFERENCE_DB.md).

### Reglas de diseño

- Evidencia sobre acusaciones · no soportado no es sospechoso
- Sin «éxito» falso para funciones no implementadas
- La exportación JSON usa hash de serie por defecto, no serie en bruto
- La carga al servidor nunca envía serie en bruto; el usuario confirma el consentimiento primero
- Las claves API de carga prefieren almacenamiento DPAPI sobre configuración en texto plano
- La revisión administrativa es solo triage humano

Política completa: [docs/security/PRIVACY.md](../security/PRIVACY.md).

---

## Avisos de terceros

IronTrace incluye **datos de referencia offline** (pci.ids, usb.ids, LOLDrivers) — véase [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md).

Las herramientas de escaneo de memoria (**hollows_hunter**, **pe-sieve**) son **de terceros, BSD-2-Clause, no incluidas** — instálelas por separado si desea el escaneo de memoria Capa 2.

---

## Roadmap

| Fase | Estado | Notas |
|------|--------|-------|
| 1 Foundation | Done (0.1.0) | App WPF, inventario PCI, motor de riesgo, exportación |
| 2 Universal integrity | Done (0.2.0) | USB, controladores, LOLDrivers, registros CI, actualizaciones de ref. firmadas |
| 3 Server challenge MVP | Done (0.3.0) | Carga con challenge, `/admin`, Docker Postgres |
| 4 Kernel evidence | Done (0.4.0) | Controlador KMDF de laboratorio, protocolo v2, esquema de informe 1.3 |
| 5 Active verification | Done (0.5.x) | Política de challenge, DOE/PCR, triage DMA/BAR/DSN |
| 6 Forensic integrity | Done (0.7.0) | Self-Audit, Full Forensic, hollows_hunter opcional |

Los canales de versión permanecen separados: aplicación, esquema de informe, API, BD de referencia, protocolo del controlador. Véase [docs/architecture/PHASED_ROADMAP.md](../architecture/PHASED_ROADMAP.md).

---

## Documentación

| Tema | Enlace |
|------|--------|
| Arquitectura | [docs/architecture/ARCHITECTURE.md](../architecture/ARCHITECTURE.md) |
| Hoja de ruta por fases | [docs/architecture/PHASED_ROADMAP.md](../architecture/PHASED_ROADMAP.md) |
| Límite del controlador | [docs/architecture/DRIVER_BOUNDARY.md](../architecture/DRIVER_BOUNDARY.md) |
| Laboratorio del controlador | [src/IronTrace.Driver/README.md](../../src/IronTrace.Driver/README.md) |
| API y carga | [docs/api/README.md](../api/README.md) |
| Modelo de amenazas | [docs/security/THREAT_MODEL.md](../security/THREAT_MODEL.md) |
| Privacidad | [docs/security/PRIVACY.md](../security/PRIVACY.md) |
| BD de referencia | [docs/database/REFERENCE_DB.md](../database/REFERENCE_DB.md) |
| pe-sieve / hollows_hunter | [docs/research/pe-sieve-hollows-hunter.md](../research/pe-sieve-hollows-hunter.md) |
| Índice de investigación | [docs/research/README.md](../research/README.md) |
| Contribución | [CONTRIBUTING.md](../../CONTRIBUTING.md) |
| Política de seguridad | [SECURITY.md](../../SECURITY.md) |

---

## Licencia y contacto

**IronTrace** — propietario. Véase [LICENSE](../../LICENSE).

**Datos y herramientas de terceros** — [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md).

**Discord:** twinkipro

Para problemas de seguridad, repórtelos de forma privada (véase [SECURITY.md](../../SECURITY.md)). No abra issues públicos para vulnerabilidades explotables hasta que haya una corrección lista.
