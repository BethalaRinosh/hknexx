PYTHON ?= python

.PHONY: install demo test reproduce

install:
	$(PYTHON) -m pip install -r requirements.txt

demo:
	$(PYTHON) scripts/reproduce_demo.py

test:
	$(PYTHON) -m pytest -q

reproduce: demo
	$(PYTHON) -m pytest -q tests/test_task2_reproduce.py
