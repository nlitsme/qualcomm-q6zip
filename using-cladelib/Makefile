CMAKE=cmake
CTEST=ctest

CMAKEARGS_LOCAL+=$(if $(D),-DCMAKE_BUILD_TYPE=Debug,-DCMAKE_BUILD_TYPE=Release)
CMAKEARGS_LOCAL+=$(if $(ASAN),-DOPT_ASAN=1)
CMAKEARGS_LOCAL+=$(if $(TSAN),-DOPT_TSAN=1)
CMAKEARGS_LOCAL+=$(if $(SYM),-DOPT_SYMBOLS=1)
CMAKEARGS_LOCAL+=$(if $(HEXAGONTOOLS),-DHEXAGONTOOLS=$(HEXAGONTOOLS))

.DEFAULT_GOAL:=all
.PHONY: all
all: build

# uses os default generator (if not GENERATOR is provided)
.PHONY: generate
generate:
	$(CMAKE) -B build $(CMAKEARGS_LOCAL)

JOBSFLAG=$(filter -j%,$(MAKEFLAGS))
# only build without regenerating build system files (prevents overwrite of previous provided ARGS for generate)
.PHONY: build
build: generate
	$(CMAKE) --build build  $(JOBSFLAG) $(if $(V),--verbose) --config $(if $(D),Debug,Release)


clean:
	$(RM) -r build
