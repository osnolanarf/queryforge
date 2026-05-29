# Query Forge

Generador de queries de hunting parametrizadas para los principales SIEM/EDR. Compón a partir de IOCs o de comportamiento (IOAs), elige plataforma y lookback, copia la query lista para tu consola.

**Demo:** https://osnolanarf.github.io/queryforge/

## Plataformas soportadas

| Plataforma | Lenguaje | IOC Hunter | IOA Hunter |
|---|---|---|---|
| Microsoft Defender XDR | KQL | ✓ | ✓ — Process · Network · File · Registry |
| CrowdStrike Falcon | CSQL / LQL (LogScale, NG-SIEM) | ✓ | 🧪 beta — Proceso · Red · DNS · ASEP |
| Palo Alto Cortex XDR | XQL | ✓ | 🧪 beta — Proceso · Red · Fichero · Registro |

> **🧪 Beta:** las queries de IOA Hunter para **CrowdStrike (LQL)** y **Cortex XDR (XQL)** están en fase beta. La generación es funcional pero todavía en validación — revisa la query antes de ejecutarla en producción. El IOA Hunter de Defender (KQL) y los tres IOC Hunter son estables.

## Cómo funciona

**IOC Hunter** — pega una lista de IOCs (hashes, IPs o dominios, uno por línea). Se acepta defanging (`1.2.3[.]4`, `hxxps://evil[.]com`). El generador clasifica por tipo y produce queries idiomáticas para cada plataforma:

- KQL — `DeviceNetworkEvents` / `DeviceFileEvents`.
- LQL (CrowdStrike) — `setTimeInterval(start=X)` + `#event_simpleName` + `select([…])`.
- XQL (Cortex) — preset por tipo de IOC.

**IOA Hunter** — describe un comportamiento (proceso, padre, abuelo, línea de comandos, usuario, ruta, registry, archivo…) y obtén la query lista para tu consola. Soporta:

- **Multi-tabla / multi-event_type** según plataforma — selector segmented en el header:
  - **KQL (Defender)**: `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`.
  - **LQL (CrowdStrike, beta)**: Proceso (`ProcessRollup2`), Red (`NetworkConnectIP4`+`IP6`), DNS (`DnsRequest`) y ASEP (`AsepValueUpdate`, solo Windows). Incluye joins entre eventos — abuelo/parent_cmdline en proceso y proceso/cmdline iniciador en red, DNS y ASEP.
  - **XQL (Cortex XDR, beta)**: Proceso, Red, Fichero y Registro sobre `xdr_data` — los tres niveles (causality → actor → action) vienen nativos en el mismo evento, sin joins.
- **Chips multi-select** para `ActionType` en File y Registry (valores cerrados como `FileCreated`, `RegistryValueSet`).
- **Chip Y / O por campo** — combina los filtros con AND por defecto; marca `O` los campos que quieras agrupar en un bloque alternativo (ej. `URL O IP`).
- **Toggle Cualquiera / Todos** (`has_any` vs `has_all`) en los campos cmdline cuando hay 2+ valores.
- **Listas dinámicas inferidas**: separa por coma para generar `let Lista = dynamic([...])` (KQL) o alternancia regex (LQL).
- **Parser tolerante a comillas**: encierra un valor entre `"…"` para preservar espacios y comas literales (p.ej. `cmdline = "c "` con espacio final intencional).
- **Normalización de PowerShell** automática a sus 4 binarios canónicos cuando el campo tiene un único valor PS.
- **Plataforma seleccionable** (Windows / Linux / macOS / Todas) en los hunters LQL y XQL.
- **Header opcional** con MITRE ATT&CK, hipótesis, descripción, falsos positivos y nivel de ruido — solo se imprime si hay metadata real.

Ambas herramientas: elige lookback y copia la query.

100 % en cliente. No hay backend ni telemetría. Los datos nunca salen del navegador.

## Stack

HTML + CSS + Vanilla JS. Sin frameworks, sin build, sin dependencias remotas. Iconos [Lucide](https://lucide.dev) servidos localmente.

## Desarrollo

Abre `index.html` directamente en el navegador. Para auto-reload usa cualquier servidor estático:

```bash
python3 -m http.server 8000
# o
npx serve
```

## Licencia

MIT — ver [LICENSE](LICENSE).
