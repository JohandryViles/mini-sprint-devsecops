# Mini Sprint DevSecOps

> ⚠️ **Proyecto con vulnerabilidades intencionales.** La API de este repositorio fue construida a propósito
> con fallos de seguridad para la práctica. No la despliegues ni la expongas a una red: se ejecuta solo en
> `127.0.0.1`. Todas las credenciales que aparecen en el código son ficticias.

## Objetivo de la práctica

Aplicar un mini sprint ágil con enfoque **DevSecOps** sobre una API vulnerable:

1. Organizar el trabajo en un tablero ágil con **historias de seguridad** y una **Definition of Done (DoD)**
   que incluya criterios de seguridad.
2. Aplicar **Shift-Left**: bloquear secretos antes de que lleguen al repositorio usando `pre-commit` y
   `detect-secrets` en el equipo de cada desarrollador.
3. Detectar y corregir vulnerabilidades: librerías con CVE conocidos (SCA), credenciales expuestas y fallos
   encontrados con análisis estático (SAST), integrando cada cambio mediante Pull Request revisado por otro
   integrante.

## Integrantes

| Integrante | Usuario de GitHub | Responsabilidad |
|---|---|---|
| Johandry Andrés Viles López | [@JohandryViles](https://github.com/JohandryViles) | Integrante 1: configuración inicial y organización |
| Integrante 2 | [@JoseAndresBruh](https://github.com/JoseAndresBruh) | Integrante 2 |
| Erick Moreira | [@Erickelrojo-22](https://github.com/Erickelrojo-22) | Integrante 3 |

## Descripción de la API

**Notas API** es una API REST hecha con **Flask** que gestiona usuarios y notas personales sobre una base de
datos **SQLite** (`data/notas.db`, se crea al iniciar). El código original se conserva en la etiqueta
[`api-original`](../../tree/api-original) para poder demostrar las vulnerabilidades aunque luego se corrijan.

### Archivos principales

| Archivo | Contenido |
|---|---|
| `app.py` | Aplicación Flask, inicialización de la base de datos y todos los endpoints. Cada fallo está marcado con `[VULN]`. |
| `config.py` | Configuración con credenciales escritas en el código (secret key, contraseña de BD, claves AWS de ejemplo, API key). |
| `requirements.txt` | Dependencias originales fijadas en versiones antiguas con CVE conocidos. |
| `files/` | Archivos que sirve el endpoint `/api/files`. |
| `.pre-commit-config.yaml` | Hook `detect-secrets` para bloquear secretos antes del commit. |
| `.secrets.baseline` | Línea base de `detect-secrets` con los secretos ya existentes en el código original. |

### Endpoints

| Método | Ruta | Descripción | Vulnerabilidad intencional |
|---|---|---|---|
| GET | `/` | Información de la API y lista de endpoints | — |
| GET | `/api/health` | Estado del servicio | — |
| POST | `/api/login` | Inicia sesión con `{"username", "password"}` | Inyección SQL, MD5 sin sal, token predecible |
| GET | `/api/users` | Lista de usuarios | Expone hashes de contraseñas sin autenticación |
| GET | `/api/users/search?name=` | Busca usuarios por nombre | Inyección SQL |
| GET | `/api/notes?user_id=` | Notas de un usuario | IDOR (sin control de acceso) |
| POST | `/api/notes` | Crea una nota | Sin autenticación |
| GET | `/api/greet?name=` | Saludo en HTML | XSS reflejado |
| GET | `/api/ping?host=` | Hace ping a un host | Inyección de comandos (`shell=True`) |
| POST | `/api/calc` | Evalúa una expresión `{"expression"}` | Ejecución de código con `eval()` |
| POST | `/api/import` | Importa datos en YAML | Deserialización insegura (`yaml.Loader`) |
| GET | `/api/files?name=` | Lee un archivo de `files/` | Path traversal |
| GET | `/api/fetch?url=` | Descarga una URL | SSRF y `verify=False` |
| GET | `/api/debug/config` | Configuración interna | Expone todos los secretos |

Además, la aplicación se ejecuta con `debug=True` (debugger de Werkzeug activo) y `requirements.txt`
contiene versiones vulnerables de Flask, Werkzeug, Jinja2, requests, urllib3, idna y PyYAML.

## Cómo ejecutar el proyecto

Requisitos: Python 3.11 o superior (probado con Python 3.14), Git y, opcionalmente, GitHub CLI.

```bash
# 1. Clonar el repositorio
gh repo clone JohandryViles/mini-sprint-devsecops
# o: git clone https://github.com/JohandryViles/mini-sprint-devsecops.git
cd mini-sprint-devsecops

# 2. Crear y activar el entorno virtual
python -m venv venv
source venv/bin/activate          # bash/zsh (Linux/macOS)
# source venv/bin/activate.fish   # fish
# venv\Scripts\activate           # Windows (PowerShell o CMD)

# 3. Instalar las dependencias originales
pip install -r requirements.txt

# 4. Ejecutar la API (crea data/notas.db y escucha en http://127.0.0.1:5000)
python app.py
```

Prueba rápida desde otra terminal:

```bash
curl http://127.0.0.1:5000/api/health
curl http://127.0.0.1:5000/api/users
curl -X POST http://127.0.0.1:5000/api/login -H "Content-Type: application/json" \
     -d '{"username": "ana", "password": "ana2026"}'
```

## Bloqueo local de secretos (pre-commit + detect-secrets)

**Cada integrante debe activarlo en su equipo** antes de hacer su primer commit:

```bash
# con el entorno virtual activado
pip install pre-commit
pre-commit install            # instala el hook en .git/hooks/pre-commit
pre-commit run --all-files    # primera ejecución (descarga detect-secrets)
```

A partir de ahí, cada `git commit` ejecuta `detect-secrets`. Si el commit contiene una credencial nueva que
no está en `.secrets.baseline`, el commit se **rechaza**. Los secretos del código original ya están
registrados en la línea base para que el hook solo bloquee secretos **nuevos**; eliminarlos del código es
parte de la historia *Eliminar credenciales expuestas*.

## Flujo de trabajo

- Tablero ágil: [GitHub Projects – Mini Sprint DevSecOps](https://github.com/users/JohandryViles/projects/3)
  con las columnas *Pendiente (Backlog)*, *En progreso*, *En revisión* y *Finalizado*.
- Historias de seguridad: [#1 Actualizar librerías vulnerables](../../issues/1),
  [#2 Eliminar credenciales expuestas](../../issues/2) y
  [#3 Corregir vulnerabilidades detectadas mediante análisis estático](../../issues/3).
- Cada historia se trabaja en una rama propia (`feature/<historia>`), y se integra a `main` solo mediante
  **Pull Request aprobado por otro integrante**.
- La Definition of Done está en [`docs/DEFINITION_OF_DONE.md`](docs/DEFINITION_OF_DONE.md).
