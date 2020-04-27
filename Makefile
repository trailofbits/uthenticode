CLANG_FORMAT := clang-format
ALL_SRCS := $(shell find src test -type f \( -name '*.cpp' -o -name '*.h' \) -print)
VERSION := $(shell cat VERSION)

.PHONY: all
all:
	@echo "This Makefile does not build anything."


.PHONY: format
format:
	$(CLANG_FORMAT) -i -style=file $(ALL_SRCS)
	git diff --exit-code


.PHONY: doc
doc:
	# Docs only: append the short hash to the version.
	VERSION=$(VERSION)-$(shell git rev-parse --short HEAD) \
		doxygen Doxyfile
