# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
VFS_OUTPUT := $(OUTPUT)/vfs
CLANG ?= clang
LIBBPF_SRC := $(abspath libbpf-bootstrap/libbpf/src)
BPFTOOL_SRC := $(abspath libbpf-bootstrap/bpftool/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
VMLINUX := $(VFS_OUTPUT)/vmlinux.h
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')
INCLUDES := -I$(VFS_OUTPUT) -I. -Iinclude -I$(OUTPUT) \
	    -Ilibbpf-bootstrap/libbpf/include/uapi
CFLAGS := -g -Wall
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n' \
		      "$(1)" \
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))" \
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

.PHONY: all
all: statediff_vfs statediff_apply_vfs

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(VFS_OUTPUT) statediff_vfs statediff_apply_vfs

$(OUTPUT) $(VFS_OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@) \
		    INCLUDEDIR= LIBDIR= UAPIDIR= \
		    install

$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

$(VMLINUX): | $(VFS_OUTPUT) $(BPFTOOL)
	$(call msg,VMLINUX,$@)
	$(Q)$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(VFS_OUTPUT)/statediff_vfs.bpf.o: statediff_vfs.bpf.c include/statediff_vfs.h $(VMLINUX) $(LIBBPF_OBJ) | $(VFS_OUTPUT) $(BPFTOOL)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		     $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) \
		     -c $< -o $(VFS_OUTPUT)/statediff_vfs.tmp.bpf.o
	$(Q)$(BPFTOOL) gen object $@ $(VFS_OUTPUT)/statediff_vfs.tmp.bpf.o

$(VFS_OUTPUT)/statediff_vfs.skel.h: $(VFS_OUTPUT)/statediff_vfs.bpf.o | $(VFS_OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

$(VFS_OUTPUT)/statediff_vfs.o: statediff_vfs.c include/statediff_vfs.h $(VFS_OUTPUT)/statediff_vfs.skel.h | $(VFS_OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(VFS_OUTPUT)/statediff_apply_vfs.o: statediff_apply_vfs.c include/statediff_vfs.h | $(VFS_OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

statediff_vfs: $(VFS_OUTPUT)/statediff_vfs.o $(LIBBPF_OBJ) | $(VFS_OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@

statediff_apply_vfs: $(VFS_OUTPUT)/statediff_apply_vfs.o | $(VFS_OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -o $@

.DELETE_ON_ERROR:
.SECONDARY:
