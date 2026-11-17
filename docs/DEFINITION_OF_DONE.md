# Definition of Done (DoD)

Una historia solo puede moverse a la columna **Finalizado** del tablero cuando cumple **todos** los criterios
siguientes.

## Criterios de seguridad (obligatorios)

1. **Sin alertas altas pendientes en los análisis de seguridad.** El código debe superar los análisis sin
   hallazgos de severidad alta o crítica abiertos:
   - SAST: `bandit -r . -x ./venv` sin hallazgos de severidad **High**.
   - SCA: `pip-audit -r requirements.txt` sin vulnerabilidades altas o críticas en las dependencias.
   - Secretos: el hook `detect-secrets` de pre-commit pasa sin errores y no se agregan secretos nuevos a
     `.secrets.baseline`.
2. **Revisión por Pull Request.** Todo cambio llega a `main` mediante un Pull Request revisado y **aprobado
   por otro integrante** del equipo (nadie aprueba su propio PR). No se hacen commits directos a `main`.

## Criterios generales

3. Los criterios de aceptación de la historia están cumplidos.
4. La API sigue arrancando con `python app.py` y los endpoints afectados se probaron manualmente.
5. Ningún secreto queda en el código: las credenciales se leen de variables de entorno y existe un
   `.env.example` sin valores reales.
6. El README y la documentación se actualizaron si cambió la forma de ejecutar o configurar el proyecto.
7. La evidencia (capturas o salidas de las herramientas) está adjunta en el issue o en el Pull Request.
