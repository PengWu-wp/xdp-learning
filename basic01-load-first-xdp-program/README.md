# basic01-load-first-xdp-program


# 中文版

这一节中，我将会以第一个示例的XDP程序，演示XDP程序的编译、挂载，以及eBPF帮助函数等基本概念。

# basic01-1

在这部分我们将使用calng和ip工具来编译和加载XDP样例程序：[xdp-drop-kern.c](./xdp-drop-kern.c)。



首先，编译和加载bpf文件需要：

* 一个编译器，将我的C程序编译成eBPF的目标文件，这里我们使用clang；
* 相关的库和头文件，我们使用libbpf；
* 一个加载器，把我的eBPF目标文件加载到指定的接口，我们使用ip，后面再自己编写加载程序；

1. 安装依赖；

   ```bash
   sudo apt install -y git build-essential clang libelf-dev 
   ```

   libelf-dev是libbpf需要用到的库，ubuntu18.04.5默认没装；

2. 克隆库、初始化子模块libbpf、编译和安装libbpf库；

   ```bash
   git clone https://github.com/PengWu-wp/xdp-learning.git xdp-learning
   cd xdp-learning
   git submodule update --init
   make libbpf
   ```

3. 进入basic01文件夹，将XDP C程序编译为eBPF目标文件，我们使用clang,这将在当前目录下生成目标文件xdp-drop-kern.o；

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

4. 使用ip工具将该文件加载到指定的接口上：

   ```bash
   sudo ip link set dev <ifname> xdp obj xdp-drop-kern.o sec xdp
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

   这时再使用`ip link \<ifname> `进行查看，即可看到xdp程序成功加载：

   ``` bash
   2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdpgeneric qdisc fq_codel state UP mode DEFAULT group default qlen 1000
       link/ether 00:0c:29:23:71:ee brd ff:ff:ff:ff:ff:ff
       prog/xdp id 40
   ```

   效果：

   该接口上的所有数据包将会被丢弃，同时每丢到一个数据包程序还会在trace_pipe文件中打印一条语句；

   可以用`sudo cat /sys/kernel/debug/tracing/trace_pipe`查看，形如：

   ```bash
         <idle>-0       [003] ..s. 51301.347725: 0: Hello, XDP and eBPF!
         <idle>-0       [003] ..s. 51312.043072: 0: Hello, XDP and eBPF!
         <idle>-0       [003] ..s. 51312.043074: 0: Hello, XDP and eBPF!
         <idle>-0       [003] ..s. 51313.043074: 0: Hello, XDP and eBPF!
         <idle>-0       [003] ..s. 51313.043695: 0: Hello, XDP and eBPF!
         <idle>-0       [003] .Ns. 51314.043093: 0: Hello, XDP and eBPF!
   avahi-daemon-764     [003] ..s. 51314.209506: 0: Hello, XDP and eBPF!
         <idle>-0       [003] ..s. 51314.554921: 0: Hello, XDP and eBPF!
         <idle>-0       [003] ..s. 51315.045391: 0: Hello, XDP and eBPF!
   ```

   
