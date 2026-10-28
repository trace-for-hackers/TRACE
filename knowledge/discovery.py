"""
knowledge/discovery.py

Ponto ÚNICO de autodiscovery de módulos, usado por
main_gui.py. É essencialmente o load_modules() que já existia dentro de
main_gui.py, extraído para aqui -- main_gui.py passa a IMPORTAR esta função
em vez de definir a sua própria, eliminando duplicação entre CLI e GUI.

Sem isso, CLI e GUI podem divergir silenciosamente em qual conjunto de
módulos é descoberto (ex.: main.py usando uma lista manual hardcoded como
hoje, enquanto main_gui.py faz scan de pasta) -- um dos dois ficaria sempre
desatualizado.
"""

from __future__ import annotations

import importlib
import os
import pkgutil
import sys


def load_modules(modules_path: str | None = None) -> list[type]:
    """
    Varre modules/*.py, importa cada arquivo, e coleta toda classe que:
      - foi definida NO PRÓPRIO arquivo (não importada de outro lugar)
      - tem um método `run`

    Funciona identicamente para módulos legados (sem @discovery_module) e
    módulos novos (decorados) -- o decorator só anexa um atributo, não
    muda a forma como a classe é descoberta.
    """
    found_modules = []

    if modules_path is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        modules_path = os.path.join(base_dir, "modules")
        if base_dir not in sys.path:
            sys.path.insert(0, base_dir)

    if not os.path.exists(modules_path):
        return []

    for _, name, _ in pkgutil.iter_modules([modules_path]):
        try:
            mod = importlib.import_module(f"modules.{name}")
            for attr in dir(mod):
                obj = getattr(mod, attr)
                if isinstance(obj, type) and hasattr(obj, "run") and obj.__module__ == f"modules.{name}":
                    found_modules.append(obj)
        except Exception as e:
            print(f"[!] Erro ao carregar módulo {name}: {e}")

    return found_modules
