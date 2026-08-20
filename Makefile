.PHONY: install test evaluate

install:
	python3 -m pip install -e '.[dev]'

test:
	pytest -q

evaluate:
	python3 evaluate.py
