.PHONY: site demo run test check package install web web-dev web-test deploy deploy-docker helm-lint bpf bpf-test
PYTHON ?= python3
NPM ?= npm
HOST ?=
CLANG ?= clang
BPF_ARCH_INCLUDE ?= /usr/include/$(shell uname -m)-linux-gnu
BPF_SOURCES := $(wildcard bpf/duvora_*.c)
BPF_OBJECTS := $(patsubst bpf/%.c,duvora/bpf/obj/%.o,$(BPF_SOURCES))

bpf: $(BPF_OBJECTS)
duvora/bpf/obj/%.o: bpf/%.c bpf/duvora_bpf.h
	@mkdir -p duvora/bpf/obj
	$(CLANG) -O2 -g -Wall -target bpf -I$(BPF_ARCH_INCLUDE) -c $< -o $@
bpf-test: bpf
	sudo DUVORA_BPF_TESTS=1 $(PYTHON) -m unittest tests.test_bpf_kernel tests.test_steer_kernel -v

demo:
	$(PYTHON) -m duvora.server --demo
run:
	$(PYTHON) -m duvora.server
test:
	$(PYTHON) -m unittest discover -s tests -v
web:
	$(NPM) --prefix web ci --no-audit --no-fund
	$(NPM) --prefix web run build
site:
	$(NPM) --prefix site ci --no-audit --no-fund
	$(NPM) --prefix site run build
web-dev:
	$(NPM) --prefix web run dev
web-test:
	$(NPM) --prefix web run typecheck
	$(NPM) --prefix web test
helm-lint:
	helm lint helm/duvora
check: test
	$(PYTHON) -m compileall -q duvora
	bash -n scripts/deploy-remote.sh scripts/deploy-container.sh
	@if [ -d web/node_modules ]; then $(MAKE) web-test; else echo "skip web-test (run make web first)"; fi
	@if command -v helm >/dev/null 2>&1; then $(MAKE) helm-lint; else echo "skip helm-lint (helm not installed)"; fi
	@if [ "$$(uname)" = Linux ] && command -v $(CLANG) >/dev/null 2>&1; then $(MAKE) bpf; else echo "skip bpf (needs Linux and clang)"; fi
package:
	$(PYTHON) scripts/package.py
install:
	$(PYTHON) -m pip install .
deploy:
	@test -n "$(HOST)" || (echo "usage: make deploy HOST=user@host" >&2; exit 2)
	./scripts/deploy-remote.sh $(HOST)
deploy-docker:
	@test -n "$(HOST)" || (echo "usage: make deploy-docker HOST=user@host" >&2; exit 2)
	./scripts/deploy-container.sh $(HOST)
