# Forwards every target to anomaly_pipeline/Makefile, e.g. `make reproduce-final`.
.DEFAULT_GOAL := help
Makefile: ;
%:
	$(MAKE) -C anomaly_pipeline $@
