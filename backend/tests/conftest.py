"""Fixtures compartidas para la suite de Project Analyzer.

Cada fixture construye un proyecto de ejemplo con características conocidas
(frameworks, secretos, vulnerabilidades, deuda técnica) para poder afirmar con
precisión qué debe detectar cada analyzer.

Cada fixture vive en su propio subdirectorio de `tmp_path` para que dos
fixtures puedan usarse en el mismo test sin mezclar archivos.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))


def _project(tmp_path: Path, name: str) -> Path:
    root = tmp_path / name
    root.mkdir(parents=True, exist_ok=True)
    return root


def _write(root: Path, rel: str, content: str) -> Path:
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return target


@pytest.fixture()
def python_api_project(tmp_path: Path) -> Path:
    """Proyecto Python + FastAPI, sin secretos ni vulnerabilidades."""
    root = _project(tmp_path, "python_api")
    _write(
        root,
        "requirements.txt",
        "fastapi==0.115.0\npydantic==2.9.2\nuvicorn>=0.30.0\n",
    )
    _write(
        root,
        "app/main.py",
        "from fastapi import FastAPI\n\napp = FastAPI()\n\n"
        "@app.get('/health')\ndef health():\n    return {'ok': True}\n",
    )
    _write(
        root,
        "app/services.py",
        "def calcular_total(items):\n"
        "    total = 0\n"
        "    for item in items:\n"
        "        if item.get('activo'):\n"
        "            total += item['precio']\n"
        "    return total\n",
    )
    _write(root, "README.md", "# Proyecto demo\n\nUn proyecto de prueba.\n")
    return root


@pytest.fixture()
def node_web_project(tmp_path: Path) -> Path:
    """Proyecto Node con React y Express."""
    root = _project(tmp_path, "node_web")
    _write(
        root,
        "package.json",
        '{\n  "name": "demo-web",\n  "dependencies": {\n'
        '    "express": "^4.19.2",\n    "react": "^18.3.1"\n  }\n}\n',
    )
    _write(
        root,
        "src/server.js",
        "const express = require('express');\nconst app = express();\n"
        "app.get('/', (req, res) => res.send('ok'));\n",
    )
    _write(root, "src/App.jsx", "export default function App() { return null; }\n")
    return root


@pytest.fixture()
def leaked_secrets_project(tmp_path: Path) -> Path:
    """Proyecto con secretos filtrados, un .env real y un .env.example legítimo."""
    root = _project(tmp_path, "leaked")
    _write(
        root,
        "config.py",
        'API_KEY = "supersecretvalue123"\n'
        'OPENAI_KEY = "sk-abcdefghijklmnopqrstuvwxyz0123456789"\n'
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n',
    )
    _write(root, ".env", "DB_PASSWORD=real-password\n")
    _write(root, ".env.example", "DB_PASSWORD=changeme\n")
    _write(root, "app.py", "import config\n\nprint(config.API_KEY)\n")
    return root


@pytest.fixture()
def vulnerable_project(tmp_path: Path) -> Path:
    """Proyecto con patrones vulnerables conocidos por el analyzer."""
    root = _project(tmp_path, "vulnerable")
    _write(
        root,
        "db.py",
        "import sqlite3\n\n\ndef get_user(conn, user_id):\n"
        '    query = f"SELECT * FROM users WHERE id = {user_id}"\n'
        "    return conn.execute(query).fetchone()\n",
    )
    _write(
        root,
        "run.py",
        "import os\n\n\ndef evaluar():\n"
        "    return eval(input('expresion: '))\n\n\n"
        "def listar(path):\n    os.system('ls ' + path)\n",
    )
    _write(
        root,
        "hashing.py",
        "import hashlib\n\n\ndef firma(valor):\n"
        "    return hashlib.md5(valor.encode()).hexdigest()\n",
    )
    return root


@pytest.fixture()
def messy_project(tmp_path: Path) -> Path:
    """Proyecto con imports sin usar y funciones largas."""
    root = _project(tmp_path, "messy")
    cuerpo = "".join(f"    valor_{i} = {i} * 2\n" for i in range(60))
    _write(
        root,
        "messy.py",
        "import json\nimport os\nimport re\n\n\ndef funcion_larga():\n" + cuerpo + "    return 0\n",
    )
    _write(root, "limpio.py", "def suma(a, b):\n    return a + b\n")
    return root


@pytest.fixture()
def clean_project(tmp_path: Path) -> Path:
    """Proyecto mínimo sin hallazgos esperados."""
    root = _project(tmp_path, "clean")
    _write(root, "main.py", "def main():\n    return 0\n")
    return root
