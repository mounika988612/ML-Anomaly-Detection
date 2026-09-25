#!/bin/bash
# Create/populate the WSL2 venv (.venv-linux). Needed because Windows Smart App Control blocks sklearn/torch DLLs.
set -e
cd "$(dirname "$0")/.."
[ -x .venv-linux/bin/python ] || python3 -m venv .venv-linux
P=.venv-linux/bin/python
$P -m pip install -q --upgrade pip
$P -m pip install -q --index-url https://download.pytorch.org/whl/cpu torch
$P -m pip install -q -r requirements.txt -r requirements-dev.txt
$P -m pip install -q -e .
$P -c "import torch, sklearn, shap, numba, ids_pipeline; print('OK torch', torch.__version__, 'sklearn', sklearn.__version__, 'shap', shap.__version__)"
