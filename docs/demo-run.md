# Demo Run

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
pytest -q
python3 evaluate.py
```

The command should complete without network access or private credentials.
