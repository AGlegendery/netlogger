PYTHON ?= python3

.PHONY: help test selftest demo install clean

help:
	@echo "make test      run the unit tests (no root needed)"
	@echo "make selftest  run the built-in parser checks"
	@echo "make demo      colourful offline demo"
	@echo "make install   install to ~/.local/bin/netlogger"
	@echo "make clean     remove __pycache__"

test:
	$(PYTHON) -m unittest discover -s tests -v

selftest:
	$(PYTHON) netlogger.py --selftest

demo:
	$(PYTHON) netlogger.py --demo

install:
	./install.sh

clean:
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
