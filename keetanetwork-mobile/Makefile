CARGO ?= cargo
WORKSPACE_DIRECTORY := $(abspath ..)
TARGET_DIRECTORY := $(WORKSPACE_DIRECTORY)/target
RELEASE_DIRECTORY := $(TARGET_DIRECTORY)/release
ifeq ($(shell uname -s),Darwin)
LIBRARY_EXTENSION := dylib
NDK_HOST := darwin-x86_64
else
LIBRARY_EXTENSION := so
NDK_HOST := linux-x86_64
endif
LIBRARY := $(RELEASE_DIRECTORY)/libkeetanetwork_mobile.$(LIBRARY_EXTENSION)
OUTPUT_DIRECTORY ?= $(TARGET_DIRECTORY)/mobile-bindings
NDK_BIN = $(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/$(NDK_HOST)/bin
ANDROID_API := 24

.PHONY: release bindings swift-host-test android-library ios-xcframework

release:
	$(CARGO) build --release -p keetanetwork-mobile --features cli

bindings: release
	$(RELEASE_DIRECTORY)/uniffi-bindgen generate $(LIBRARY) --language swift --out-dir $(OUTPUT_DIRECTORY)/swift
	$(RELEASE_DIRECTORY)/uniffi-bindgen generate $(LIBRARY) --language kotlin --no-format --out-dir $(OUTPUT_DIRECTORY)/kotlin

swift-host-test: bindings
	swiftc -module-name KeetaMobileHostTest \
		-I $(OUTPUT_DIRECTORY)/swift \
		-Xcc -fmodule-map-file=$(OUTPUT_DIRECTORY)/swift/keetanetwork_mobileFFI.modulemap \
		-L $(RELEASE_DIRECTORY) -lkeetanetwork_mobile \
		tests/swift/main.swift $(OUTPUT_DIRECTORY)/swift/keetanetwork_mobile.swift \
		-o $(OUTPUT_DIRECTORY)/swift-host-test
	DYLD_LIBRARY_PATH=$(RELEASE_DIRECTORY) LD_LIBRARY_PATH=$(RELEASE_DIRECTORY) $(OUTPUT_DIRECTORY)/swift-host-test $(CURDIR)/tests/fixtures/web-vectors.json

android-library:
	CC_aarch64_linux_android=$(NDK_BIN)/aarch64-linux-android$(ANDROID_API)-clang \
	AR_aarch64_linux_android=$(NDK_BIN)/llvm-ar \
	CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$(NDK_BIN)/aarch64-linux-android$(ANDROID_API)-clang \
	$(CARGO) build --release -p keetanetwork-mobile --lib --target aarch64-linux-android

ios-xcframework: bindings
	$(CARGO) build --release -p keetanetwork-mobile --lib --target aarch64-apple-ios --target aarch64-apple-ios-sim
	rm -rf $(OUTPUT_DIRECTORY)/ios-headers $(OUTPUT_DIRECTORY)/KeetaNetworkMobile.xcframework
	mkdir -p $(OUTPUT_DIRECTORY)/ios-headers
	cp $(OUTPUT_DIRECTORY)/swift/keetanetwork_mobileFFI.h $(OUTPUT_DIRECTORY)/ios-headers/
	cp $(OUTPUT_DIRECTORY)/swift/keetanetwork_mobileFFI.modulemap $(OUTPUT_DIRECTORY)/ios-headers/module.modulemap
	xcodebuild -create-xcframework \
		-library $(TARGET_DIRECTORY)/aarch64-apple-ios/release/libkeetanetwork_mobile.a -headers $(OUTPUT_DIRECTORY)/ios-headers \
		-library $(TARGET_DIRECTORY)/aarch64-apple-ios-sim/release/libkeetanetwork_mobile.a -headers $(OUTPUT_DIRECTORY)/ios-headers \
		-output $(OUTPUT_DIRECTORY)/KeetaNetworkMobile.xcframework
