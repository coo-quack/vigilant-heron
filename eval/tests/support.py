"""Shared helpers for the eval script tests."""

import importlib.util
import pathlib

EVAL_DIR = pathlib.Path(__file__).resolve().parent.parent
ROOT = EVAL_DIR.parent
DATASET_DIR = EVAL_DIR / "dataset"


def load_script(name):
    """Imports eval/<name>.py under a unique module name, without running its main()."""
    spec = importlib.util.spec_from_file_location(f"eval_{name}", EVAL_DIR / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
