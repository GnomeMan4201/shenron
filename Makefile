.PHONY: init lint test fmt typecheck clean

init:
\tpython -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]" && pre-commit install

lint:
\truff check .
\tmypy shenron_core || true

fmt:
\truff check --fix .

test:
\tpytest -q

clean:
\trm -rf .venv dist build *.egg-info .pytest_cache
