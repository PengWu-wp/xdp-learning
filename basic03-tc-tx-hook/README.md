# basic 03-tc-tx-hook



# 中文版

这节主要是要用tc钩子，用于egress挂载eBPF程序，挂载程序的具体作用是检查是否是来自
Redis服务端的报文（Redis服务端默认源端口为6379），是的话向trace_pipe输出一条信息。

挂载流程：

```bash
tc qdisc add dev ens38 clsact
tc filter add dev ens38 egress bpf da obj tc-prog-kern.o sec tx_prog
```

要取消挂载：

```bash
tc filter del dev ens38 egress
```

