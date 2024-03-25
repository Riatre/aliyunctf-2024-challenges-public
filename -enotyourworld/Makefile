TRIPLET ?= loongarch64-linux-gnu-
CC = $(TRIPLET)gcc
BUILDDIR = $(CURDIR)/build

all: $(BUILDDIR)/chal

$(BUILDDIR)/chal: $(BUILDDIR)/chal.o stub.py
	-rm -f $@
	(cat stub.py; python3 -c "O=__import__('base64').a85encode(__import__('lzma').compress(open(__import__('sys').argv[1], 'rb').read()));print(f'{O=}')" $(BUILDDIR)/chal.o) > $@
	chmod +x $@

$(BUILDDIR)/chal.o: $(BUILDDIR)/main.o chal.py lang.py params.py flag
	./chal.py -o $@ --flag_file flag $(BUILDDIR)/main.o

$(BUILDDIR)/main.o: main.c
	mkdir -p $(BUILDDIR)
	$(CC) -c -o $@ $<

params.py: genpoly.py flag
	sage $< > $@

test: $(BUILDDIR)/chal.o
	$(CC) -static -o $(BUILDDIR)/good $(BUILDDIR)/chal.o \
	-Wl,--defsym=v0=8386668381921176673 \
	-Wl,--defsym=v1=7592914393331170150 \
	-Wl,--defsym=v2=8319669632023945075 \
	-Wl,--defsym=v3=8097868363955333492 \
	-Wl,--defsym=v4=7453016957694998896 \
	-Wl,--defsym=v5=6874579214866146681 \
	-Wl,--defsym=v6=3559048006806418532 \
	-Wl,--defsym=v7=9023363456357660501 \
	2>/dev/null
	$(BUILDDIR)/good
	$(CC) -static -o $(BUILDDIR)/bad $(BUILDDIR)/chal.o \
	-Wl,--defsym=v0=1 \
	-Wl,--defsym=v1=7592914393331170150 \
	-Wl,--defsym=v2=8319669632023945075 \
	-Wl,--defsym=v3=8097868363955333492 \
	-Wl,--defsym=v4=2 \
	-Wl,--defsym=v5=6874579214866146681 \
	-Wl,--defsym=v6=3 \
	-Wl,--defsym=v7=9023363456357660501 \
	2>/dev/null
	$(BUILDDIR)/bad

pytest:
	pytest tests.py

clean:
	-rm -rf $(BUILDDIR)

.PHONY: test clean pytest
