"""Configuracion de la API Notas.

ADVERTENCIA (intencional para la practica): las credenciales estan escritas
directamente en el codigo fuente. Son valores FICTICIOS que no dan acceso a
ningun sistema real, pero representan la mala practica que el equipo debe
corregir en la historia "Eliminar credenciales expuestas".
"""

DEBUG = True

SECRET_KEY = "s3cr3t-k3y-n0t4s-2026-pr0duccion"

DATABASE_PATH = "data/notas.db"
DATABASE_USER = "admin"
DATABASE_PASSWORD = "Admin2026!SuperSegura"

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

# Claves de ejemplo publicadas en la documentacion de AWS (no son reales).
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

PAYMENTS_API_KEY = "pk_live_9f8e7d6c5b4a39281706f5e4d3c2b1a0"
