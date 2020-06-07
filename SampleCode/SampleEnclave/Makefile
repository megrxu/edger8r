######## Enclave Settings ########

SGX_EDGER8R = ../../../_build/Edger8r.native
SEARCH_PATH = --search-path ../Enclave --search-path ../Include

.PHONY: all
all: App/Enclave_u.h App/Enclave_u.c Enclave/Enclave_t.h Enclave/Enclave_t.c

######## EDGER8R generate files ########

App/Enclave_u.h: Enclave/Enclave.edl
	@cd App && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl $(SEARCH_PATH)
	@echo "GEN  =>  $@"

App/Enclave_u.c: App/Enclave_u.h

Enclave/Enclave_t.h: Enclave/Enclave.edl
	@cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/Enclave.edl $(SEARCH_PATH)
	@echo "GEN  =>  $@"

Enclave/Enclave_t.c: Enclave/Enclave_t.h

######## Clean ########

.PHONY: clean

clean:
	@rm -f App/Enclave_u.* Enclave/Enclave_t.*
