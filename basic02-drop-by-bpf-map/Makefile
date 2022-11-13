CC := clang

BPF_CFLAGS := -g -O2 -target bpf -Werror -Wall -c
CFLAGS := -g -Werror -Wall

EXECABLE = xdp_prog_user
BPFCODE = xdp_prog_kern

LIBS = -l:libbpf.a -lelf -lz

.PHONY: clean $(BPFCODE:=.c)

clean:
	rm -f *.o $(EXECABLE)

$(BPFCODE:=.o): $(BPFCODE:=.c)
	$(CC) $(BPF_CFLAGS) $(BPFCODE:=.c) -o $(BPFCODE:=.o)

$(EXECABLE): $(BPFCODE:=.o)
	$(CC) $(CFLAGS) $(EXECABLE:=.c) -o $(EXECABLE) $(LIBS)

.DEFAULT_GOAL := $(EXECABLE)
