# Auditoría de dependencias y decisiones de mitigación

**U3_A4 · Erick Moreira · Integrante 2**
Para el integrante 3, responsable de la remediación.

El análisis se realizó el 18 de noviembre de 2026 sobre `requirements.txt` del commit `5ab2c41` de `JohandryViles/mini-sprint-devsecops`. pip-audit 2.10.1 consultó el servicio de avisos de PyPI y terminó con código 1. La salida contiene 63 registros de avisos en 8 de 13 dependencias. Al agrupar por identificador GHSA dentro de cada paquete quedan 33 avisos distintos, de los cuales 32 tienen CVE y uno solo tiene identificador GHSA en la salida.

El riesgo corresponde a la severidad publicada por GitHub Advisory Database, enlazada en cada fila. Las versiones de la última columna son las correcciones informadas para cada aviso. Para actualizar cada paquete, elige una versión compatible que cubra todos sus avisos y vuelve a auditar el entorno completo. Verifica en conjunto Flask, Werkzeug y Jinja2, y también requests, urllib3 e idna, para evitar conflictos entre requisitos.

| Dependencia afectada | CVE o aviso | Riesgo | Decisión |
| --- | --- | --- | --- |
| Flask 2.3.3 | [CVE-2026-27205](https://github.com/advisories/GHSA-68rp-wp8r-4726) | Bajo | Actualizar. Versiones corregidas 3.1.3. |
| Werkzeug 2.3.7 | [CVE-2026-27199](https://github.com/advisories/GHSA-29vq-49wr-vm6x) | Medio | Actualizar. Versiones corregidas 3.1.6. |
| Werkzeug 2.3.7 | [CVE-2024-34069](https://github.com/advisories/GHSA-2g68-c3qc-8985) | Alto | Actualizar. Versiones corregidas 3.0.3. |
| Werkzeug 2.3.7 | [CVE-2026-21860](https://github.com/advisories/GHSA-87hc-h4r5-73f7) | Medio | Actualizar. Versiones corregidas 3.1.5. |
| Werkzeug 2.3.7 | [CVE-2024-49766](https://github.com/advisories/GHSA-f9vj-2wh5-fj8j) | Medio | Actualizar. Versiones corregidas 3.0.6. |
| Werkzeug 2.3.7 | [CVE-2026-102598](https://github.com/advisories/GHSA-g6x2-hccm-hh4m) | Medio | Actualizar. Versiones corregidas 3.1.9. |
| Werkzeug 2.3.7 | [CVE-2025-66221](https://github.com/advisories/GHSA-hgf8-39gv-g3f2) | Medio | Actualizar. Versiones corregidas 3.1.4. |
| Werkzeug 2.3.7 | [CVE-2023-46136](https://github.com/advisories/GHSA-hrfv-mqp8-q5rw) | Medio | Actualizar. Versiones corregidas 2.3.8, 3.0.1. |
| Werkzeug 2.3.7 | [CVE-2024-49767](https://github.com/advisories/GHSA-q34m-jh98-gwm2) | Medio | Actualizar. Versiones corregidas 3.0.6. |
| Jinja2 3.1.2 | [CVE-2025-27516](https://github.com/advisories/GHSA-cpwx-vrp4-4pq7) | Medio | Actualizar. Versiones corregidas 3.1.6. |
| Jinja2 3.1.2 | [CVE-2024-56201](https://github.com/advisories/GHSA-gmj6-6f8f-6699) | Medio | Actualizar. Versiones corregidas 3.1.5. |
| Jinja2 3.1.2 | [CVE-2024-22195](https://github.com/advisories/GHSA-h5c8-rqwp-cp95) | Medio | Actualizar. Versiones corregidas 3.1.3. |
| Jinja2 3.1.2 | [CVE-2024-34064](https://github.com/advisories/GHSA-h75v-3vvj-5mfj) | Medio | Actualizar. Versiones corregidas 3.1.4. |
| Jinja2 3.1.2 | [CVE-2024-56326](https://github.com/advisories/GHSA-q2x7-8rv6-6q7h) | Medio | Actualizar. Versiones corregidas 3.1.5. |
| requests 2.25.1 | [CVE-2024-47081](https://github.com/advisories/GHSA-9hjg-9r4m-mvj7) | Medio | Actualizar. Versiones corregidas 2.32.4. |
| requests 2.25.1 | [CVE-2024-35195](https://github.com/advisories/GHSA-9wx4-h78v-vm56) | Medio | Actualizar. Versiones corregidas 2.32.0. |
| requests 2.25.1 | [CVE-2026-25645](https://github.com/advisories/GHSA-gc5v-m9x4-r6x2) | Medio | Actualizar. Versiones corregidas 2.33.0. |
| requests 2.25.1 | [CVE-2023-32681](https://github.com/advisories/GHSA-j8r2-6x86-q33q) | Medio | Actualizar. Versiones corregidas 2.31.0. |
| urllib3 1.26.15 | [CVE-2025-66471](https://github.com/advisories/GHSA-2xpw-w6gg-jr37) | Alto | Actualizar. Versiones corregidas 2.6.0. |
| urllib3 1.26.15 | [CVE-2024-37891](https://github.com/advisories/GHSA-34jh-p97f-mpxf) | Medio | Actualizar. Versiones corregidas 1.26.19, 2.2.2. |
| urllib3 1.26.15 | [CVE-2026-21441](https://github.com/advisories/GHSA-38jv-5279-wg99) | Alto | Actualizar. Versiones corregidas 2.6.3. |
| urllib3 1.26.15 | [CVE-2026-97687](https://github.com/advisories/GHSA-8988-9cw3-xx77) | Alto | Actualizar. Versiones corregidas 2.8.0. |
| urllib3 1.26.15 | [CVE-2023-45803](https://github.com/advisories/GHSA-g4mx-q9vg-27p4) | Medio | Actualizar. Versiones corregidas 1.26.18, 2.0.7. |
| urllib3 1.26.15 | [CVE-2025-66418](https://github.com/advisories/GHSA-gm62-xv2j-4w53) | Alto | Actualizar. Versiones corregidas 2.6.0. |
| urllib3 1.26.15 | [CVE-2025-50181](https://github.com/advisories/GHSA-pq67-6m6q-mj2v) | Medio | Actualizar. Versiones corregidas 2.5.0. |
| urllib3 1.26.15 | [CVE-2026-44431](https://github.com/advisories/GHSA-qccp-gfcp-xxvc) | Alto | Actualizar. Versiones corregidas 2.7.0. |
| urllib3 1.26.15 | [CVE-2023-43804](https://github.com/advisories/GHSA-v845-jxx5-vc9f) | Alto | Actualizar. Versiones corregidas 1.26.17, 2.0.6. |
| urllib3 1.26.15 | [CVE-2026-97689](https://github.com/advisories/GHSA-vxq7-64xx-v4gw) | Alto | Actualizar. Versiones corregidas 2.8.0. |
| idna 2.10 | [CVE-2026-45409](https://github.com/advisories/GHSA-65pc-fj4g-8rjx) | Medio | Actualizar. Versiones corregidas 3.15. |
| idna 2.10 | [CVE-2024-3651](https://github.com/advisories/GHSA-jjg7-2v4v-x38h) | Medio | Actualizar. Versiones corregidas 3.7. |
| certifi 2023.7.22 | [CVE-2024-39689](https://github.com/advisories/GHSA-248v-346w-9cwc) | Bajo | Actualizar. Versiones corregidas 2024.7.4. |
| certifi 2023.7.22 | [GHSA-6q48-6c7w-9gw2 (sin CVE en la salida)](https://github.com/advisories/GHSA-6q48-6c7w-9gw2) | Crítico | Actualizar. Versiones corregidas 2026.10.18. |
| PyYAML 5.3.1 | [CVE-2020-14343](https://github.com/advisories/GHSA-8q59-q68h-6hv4) | Crítico | Actualizar. Versiones corregidas 5.4. |

## Reproducción y criterio del pipeline

La [salida JSON](pip-audit.json) conserva los registros originales. La auditoría local consultó las versiones exactas declaradas en el manifiesto. El [SBOM CycloneDX 1.6](../../sbom.json) se generó con CycloneDX Python 8.0.1 a partir del mismo archivo.

```shell
cyclonedx-py requirements requirements.txt --output-reproducible --spec-version 1.6 --output-format JSON -o sbom.json
pip-audit --no-deps --disable-pip -r requirements.txt --desc off --format json --output docs/auditoria/pip-audit.json
```

En GitHub Actions, Bandit bloquea alertas altas y pip-audit bloquea cualquier vulnerabilidad conocida de las dependencias instaladas, incluidas las transitivas. Al abrir un PR de remediación, vuelve a generar `sbom.json` con el manifiesto actualizado y verifica los checks `SAST (Bandit)` y `SCA (pip-audit)`.
