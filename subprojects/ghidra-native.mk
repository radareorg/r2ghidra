# Maintained separately from acr-wrap: use upstream's patch target and preserve
# local changes when switching versions. The wrap owns the URL and version pin.

GHIDRA_NATIVE_URL=$(shell sed -n 's/^url *= *//p' ghidra-native.wrap)
GHIDRA_NATIVE_REVISION=$(shell sed -n 's/^revision *= *//p' ghidra-native.wrap)

.PHONY: ghidra-native ghidra-native_clean ghidra-native_all

ghidra-native:
	@set -e; \
	if [ ! -d ghidra-native ]; then \
		git clone --depth=1 "$(GHIDRA_NATIVE_URL)" ghidra-native; \
	elif [ ! -e ghidra-native/.git ]; then \
		echo "ghidra-native exists but is not a git checkout" >&2; exit 1; \
	fi; \
	revision=$$(git -C ghidra-native rev-parse --verify '$(GHIDRA_NATIVE_REVISION)^{commit}' 2>/dev/null || git -C ghidra-native rev-parse --verify 'refs/r2ghidra/$(GHIDRA_NATIVE_REVISION)^{commit}' 2>/dev/null || true); \
	prepare=0; \
	if [ "$$(git -C ghidra-native rev-parse --verify HEAD)" != "$$revision" ]; then \
		if [ -z "$$revision" ]; then \
			git -C ghidra-native fetch --depth=1 "$(GHIDRA_NATIVE_URL)" "$(GHIDRA_NATIVE_REVISION)"; \
			revision=$$(git -C ghidra-native rev-parse --verify FETCH_HEAD); \
			git -C ghidra-native update-ref 'refs/r2ghidra/$(GHIDRA_NATIVE_REVISION)' "$$revision"; \
		fi; \
		prepare=1; \
	elif [ ! -f ghidra-native/patch.done ] && ! git -C ghidra-native diff --quiet; then \
		prepare=1; \
	fi; \
	if [ "$$prepare" = 1 ]; then \
		git -C ghidra-native stash push --include-untracked -m "r2ghidra: before updating ghidra-native to $(GHIDRA_NATIVE_REVISION)"; \
		git -C ghidra-native checkout --detach "$$revision"; \
		rm -f ghidra-native/patch.done; \
	fi
	$(MAKE) -C ghidra-native patch

ghidra-native_all: ghidra-native

ghidra-native_clean:
	rm -rf ghidra-native
