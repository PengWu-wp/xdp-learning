CC := clang

BPF_CFLAGS := -O2 -target bpf -Werror -Wall -c -I../libbpf/include/uapi/
CFLAGS := -g -Werror -Wall -I../libbpf/include/uapi/

EXECABLE = af-xdp-user
BPFCODE = af-xdp-kern

LIBS = -l:libbpf.a -lelf -lpthread

.PHONY: clean $(BPFCODE:=.c)

clean:
	rm -f *.o $(EXECABLE)

$(BPFCODE:=.o): $(BPFCODE:=.c)
	$(CC) $(BPF_CFLAGS) $(BPFCODE:=.c) -o $(BPFCODE:=.o)

$(EXECABLE): $(BPFCODE:=.o)
	$(CC) $(CFLAGS) $(EXECABLE:=.c) -o $(EXECABLE) $(LIBS)

.DEFAULT_GOAL := $(EXECABLE)
