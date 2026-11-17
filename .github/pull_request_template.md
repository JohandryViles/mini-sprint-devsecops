## Historia relacionada

Closes #

## Cambios realizados

-

## Evidencia

<!-- Adjunta capturas o salidas de bandit, pip-audit y pre-commit -->

## Checklist de la Definition of Done

- [ ] `bandit -r . -x ./venv` no reporta hallazgos de severidad High.
- [ ] `pip-audit -r requirements.txt` no reporta vulnerabilidades altas o críticas.
- [ ] `pre-commit run --all-files` pasa (sin secretos nuevos).
- [ ] La API arranca con `python app.py` y probé los endpoints afectados.
- [ ] No hay credenciales en el código (se usan variables de entorno).
- [ ] Documentación actualizada si aplica.
- [ ] Solicité revisión a otro integrante; no apruebo mi propio PR.
