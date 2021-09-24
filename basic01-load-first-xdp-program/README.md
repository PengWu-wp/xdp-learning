# basic01-load-first-xdp-program


# 中文版

这一节中，我将会以第一个示例的XDP程序，演示XDP程序的编译、挂载，以及eBPF帮助函数等基本概念。

# Start

首先，我们需要将XDP C程序编译为eBPF目标文件，我们使用clang：

``` bash
clang -O2 -target bpf -Werror -Wall -c xdp-drop-kern.c -o xdp-drop-kern.o
```

> -O2：优化设置为2；
>
> -target bpf：将目标文件编译为eBPF程序；
>
> -Werror -Wall：与warning相关的设置；
>
> -c：只进行preprocess、compile和assemble三个步骤；
>
> -o xdp-drop-kern.o：指定输出文件； 

这将在当前目录下生成目标文件xdp-drop-kern.o，之后可以使用ip工具将该文件加载到指定的接口上：

```bash
ip link set dev <ifname> xdp obj xdp-drop-kern.o sec xdp
```

> link：配置网络接口
>
> set：更改设备属性
>
> dev <ifname>：指定要操作的网络设备
>
> xdp：这里可以指定xdp/xdpgeneric/xdpdrv/xdpoffload的其中一种；xdp根据网卡驱动的支持，自动决定使用xdpdrv或回退回xdpgeneric模式；xdpgeneric即通用模式，SKB模式；xdpdrv即驱动模式，native原生模式；xdpoffload为卸载模式，目前仅有Netronome网卡支持；
>
> obj xdp-drop-kern.o：指定从xdp-drop-kern.o的ELF文件中加载XDP程序；
>
> sec xdp：指定从ELF文件中加载的eBPF程序，即我们在[xdp-drop-kern.c](./xdp-drop-kern.c)中通过SEC(xdp)指定的section name，若未在程序中指定，这里需要使用默认的sec .text；

这时再使用ip link \<ifname> 进行查看，即可看到xdp程序成功加载：

``` bash
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdpgeneric qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether 00:0c:29:23:71:ee brd ff:ff:ff:ff:ff:ff
    prog/xdp id 40
```
  
加载成功后，该XDP程序会在每接收到一个数据包的时候向/sys/kernel/debug/tracing/trace_pipe打印一条"Hello, XDP and eBPF!"，并丢弃该接口上收到的每一个包。打开预装的火狐浏览器就可以测试了。


