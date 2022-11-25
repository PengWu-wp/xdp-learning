CC := clang

BPF_CFLAGS := -O2 -target bpf -Werror  -c -I../libbpf/include/uapi/
# CFLAGS := -g -Werror  -I../libbpf/include/uapi/

# EXECABLE = tc_prog_user
BPFCODE = tc_prog_kern

LIBS = -l:libbpf.a -lelf

.PHONY: clean $(BPFCODE:=.c)


$(BPFCODE:=.o): $(BPFCODE:=.c)
	$(CC) $(BPF_CFLAGS) $(BPFCODE:=.c) -o $(BPFCODE:=.o)

clean:
	rm -f *.o $(EXECABLE)
