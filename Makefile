PYTHON ?= python

.PHONY: install demo test reproduce

install:
	$(PYTHON) -m pip install -r requirements.txt

demo:
	@rm -rf out/demo
	@mkdir -p out/demo
	$(PYTHON) -m backend.cli analyze data/sample/attack.json --out out/demo/attack --config config/rules.yml
	$(PYTHON) -m backend.cli analyze data/sample/clean.json --out out/demo/clean --config config/rules.yml

test:
	$(PYTHON) -m pytest -q

reproduce: demo
	$(PYTHON) -m pytest -q tests/test_task2_reproduce.py
