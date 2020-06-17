CLANG_FORMAT := clang-format
ALL_SRCS := $(shell find src test -type f \( -name '*.cpp' -o -name '*.h' \) -print)
ALL_LISTFILES := $(shell find src test cmake -type f \( -name 'CMakeLists.txt' -o -name '*.cmake' \) -print)
VERSION := $(shell cat VERSION)

PEPARSE_VERSION ?= v1.2.0

.PHONY: all
all:
	@echo "This Makefile does not build anything."


.PHONY: format
format: clang-format cmake-format

.PHONY: clang-format
clang-format:
	$(CLANG_FORMAT) -i -style=file $(ALL_SRCS)
	git diff --exit-code

.PHONY: cmake-format
cmake-format:
	cmake-format -i $(ALL_LISTFILES)
	git diff --exit-code

.PHONY: doc
doc:
	# Docs only: append the short hash to the version.
	VERSION=$(VERSION)-$(shell git rev-parse --short HEAD) \
		doxygen Doxyfile

.PHONY: docker
docker:
	DOCKER_BUILDKIT=1 docker build -t uthenticode --build-arg PEPARSE_VERSION=$(PEPARSE_VERSION) .
