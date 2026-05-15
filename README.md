# Query Forge

Generador de queries de hunting parametrizadas para los principales SIEM/EDR. Pega IOCs, elige plataforma y lookback, copia la query lista para tu consola.

**Demo:** https://osnolanarf.github.io/queryforge/

## Plataformas soportadas

| Plataforma | Lenguaje |
|---|---|
| Microsoft Defender XDR | KQL |
| CrowdStrike Falcon | CSQL (LogScale / NG-SIEM) |
| Palo Alto Cortex XDR | XQL |

## Cómo funciona

1. Pega una lista de IOCs (hashes, IPs o dominios — uno por línea). Se acepta defanging (`1.2.3[.]4`, `hxxps://evil[.]com`).
2. Elige plataforma y lookback (1 h – 180 d).
3. Copia la query generada y pégala en la consola de tu SIEM.

Los IOCs se clasifican automáticamente por tipo (IP, dominio, MD5, SHA1, SHA256) y se generan queries idiomáticas para cada plataforma.

100 % en cliente. No hay backend ni telemetría. Los IOCs nunca salen del navegador.

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
