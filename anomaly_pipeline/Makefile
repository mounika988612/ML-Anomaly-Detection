# Reproduction targets for the thesis (run from Git Bash; make is available in conda: `conda install -n mlenv -c conda-forge make`).
# Interpreter: activate mlenv, or pass PY=/d/SoftwareTools/Users/maida/anaconda3/envs/mlenv/python.exe
#
#   make reproduce-final         regenerate every final table and report from the saved models/scores and verify the numbers (~5 h)
#   make reproduce-<step>        one step: prepare eda e7 e9 e10 crossdata x2 e11 e12 e13 x3 x4 (then verification of that step)
#   make test                    unit tests (pytest)
#   make retrain-final CONFIRM=1 retrain every final model from the data, then reproduce and verify (~12-15 h; overwrites results)
#   make dataset CONFIRM=1       rebuild CIC-IDS2017 from the official pcaps with Suricata, and run Zeek (Docker, ~6 h)
#   make clean-cache             delete disposable caches (work folders of P2 / UNSW / CSE-CIC-IDS2018, tool caches)

PY ?= python
export PY
SHELL := bash
DAYS := Monday Tuesday Wednesday Thursday Friday
ZEEK_DAYS := Tuesday Wednesday Thursday Friday
ZEEK_IMAGE := zeek/zeek:9.0.0

.PHONY: help reproduce-final retrain-final dataset test clean-cache

help:
	@sed -n '1,12p' Makefile

reproduce-final:
	bash scripts/reproduce_final.sh

reproduce-%:
	bash scripts/reproduce_final.sh $*

test:
	$(PY) -m pytest -q

retrain-final:
	CONFIRM=$(CONFIRM) bash scripts/retrain_final.sh

dataset:
	@[ "$(CONFIRM)" = "1" ] || { echo "dataset rebuilds ../external/cic2017 (the CIC-IDS2017 parquet used by every model); rerun with CONFIRM=1"; exit 2; }
	for d in $(DAYS); do \
	  bash logs/run_E7.sh sensors $$d ../dataset/CICIDS2017/$$(ls ../dataset/CICIDS2017 | grep -i "^$$d-") || exit 1; \
	done
	bash logs/run_E7.sh parquet
	export MSYS_NO_PATHCONV=1; PD=$$(cygpath -w "$$(cd ../dataset/CICIDS2017 && pwd)" 2>/dev/null || (cd ../dataset/CICIDS2017 && pwd)); \
	for d in $(ZEEK_DAYS); do \
	  f=$$(ls ../dataset/CICIDS2017 | grep -i "^$$d-"); mkdir -p ../external/cic2017/$$d/zeek; \
	  OD=$$(cygpath -w "$$(cd ../external/cic2017/$$d && pwd)" 2>/dev/null || (cd ../external/cic2017/$$d && pwd)); \
	  docker run --rm --network none -v "$$PD:/pcap:ro" -v "$$OD:/out" -w /out/zeek $(ZEEK_IMAGE) zeek -C -r "/pcap/$$f" local \
	    protocols/ftp/detect-bruteforcing protocols/ssl/heartbleed misc/detect-traceroute "Site::local_nets += { 192.168.10.0/24 }" || exit 1; \
	done

clean-cache:
	rm -rf work_suricata2017_rebuilt work_multiday_context_clean work_unsw work_cic2017_monday/e12_cache .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
