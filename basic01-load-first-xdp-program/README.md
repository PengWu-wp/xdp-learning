# basic01-load-first-xdp-program


# 中文版

这一节中，我将会以第一个示例的XDP程序，演示XDP程序的编译、挂载，以及eBPF帮助函数等基本概念。

## basic01-1

在这部分我们将使用clang和ip工具来编译和加载XDP样例程序：[xdp-drop-kern.c](./xdp-drop-kern.c)。（Makefile已更新）



首先，编译和加载bpf文件需要：

* 一个编译器，将我的C程序编译成eBPF的目标文件，这里我们使用clang；
* 相关的库和头文件，我们使用github上单独维护的[libbpf](../libbpf)；
* 一个加载器，把我的eBPF目标文件加载到指定的接口，我们使用ip工具，后面再自己编写加载程序；

具体步骤：

1. 安装依赖；

   ```bash
   sudo apt install -y git build-essential clang libelf-dev pkg-config gcc-multilib
   ```

   libelf-dev是libbpf需要用到的库；

   gcc-multilib适用于交叉编译，没有这个包，一些头文件会找不到；

2. 克隆库，初始化子模块libbpf，运行脚本以编译安装libbpf库和头文件；

   ```bash
   git clone https://github.com/PengWu-wp/xdp-learning.git xdp-learning
   cd xdp-learning
   git submodule update --init
   ./install_libbpf.sh
   ```

   > 注：libbpf已更新至v1.0.1，涉及不少API和规则的变动，暂时不准备像[xdp-tools](https://github.com/xdp-project/xdp-tools)那样
   > 支持新老版本的libbpf。
   >
   > 脚本会编出libbpf库，并把头文件放到编译器可以直接找到的地方，方便起见我们后面使用静态库libbpf.a

3. 进入basic01文件夹，将XDP C程序编译为eBPF目标文件，我们使用clang,这将在当前目录下生成目标文件xdp-drop-kern.o；

   ``` bash
   clang -g -O2 -target bpf -Werror -Wall -c xdp-drop-kern.c -o xdp-drop-kern.o
   ```

   > -g: 生成BTF；
   > 
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
   > xdp：这里可以指定xdp/xdpgeneric/xdpdrv/xdpoffload的其中一种；xdp根据网卡驱动的支持，自动决定使用xdpdrv或回退回xdpgeneric模式；xdpgeneric即通用模式，SKB模式；xdpdrv即驱动模式，native原生模式；xdpoffload为卸载模式，需要网卡的支持；
   >
   > obj xdp-drop-kern.o：指定从xdp-drop-kern.o的ELF文件中加载XDP程序；
   >
   > sec xdp：指定从ELF文件中加载的eBPF程序，即我们在[xdp-drop-kern.c](./xdp-drop-kern.c)中通过SEC(xdp)指定的section name，若未在程序中指定，这里需要使用默认的sec .text；

   这时再使用`ip link show <ifname> `进行查看，即可看到xdp程序成功加载：

   ``` bash
   2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdpgeneric qdisc fq_codel state UP mode DEFAULT group default qlen 1000
       link/ether 00:0c:29:23:71:ee brd ff:ff:ff:ff:ff:ff
       prog/xdp id 40
   ```

   效果：

   该接口上的所有数据包将会被丢弃，同时每丢到一个数据包程序还会在trace_pipe文件中打印一条语句；

   可以用`sudo cat /sys/kernel/debug/tracing/trace_pipe`查看，用于简单的xdp程序debug还是很有用的；
   
   > 注：offload模式不能用该帮助函数，否则无法加载；

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

5. 若要使用ip工具卸载xdp程序：

   ```bash
   sudo ip link set dev <ifname> xdp off
   ```

## basic01-2

然后我们开始手动编写加载器，用C就好；这里有多种加载方式和函数可以用；还可以用BCC来加载；

我们用libbpf库，编写一个简单的加载器，代码为[loader.c](./loader.c)，第一个示例程序就把
所有函数都放main里面了，能大概了解一下XDP程序加载所需步骤。

1. 到basic01文件夹，编译出加载器的可执行文件；

   ```bash
   clang -g -Wall -o loader loader.c -l:libbpf.a -lelf -lz
   ```

2. 加载器的使用方式：

   ```bash
   usage ./loader [options] 
   
   Requried options:
   -d, --dev <ifname>		Specify the device <ifname>
   
   Other options:
   -h, --help		this text you see right here
   -S, --skb-mode	Install XDP program in SKB (AKA generic) mode
   -N, --native-mode	Install XDP program in native mode
   -O, --offload-mode	Install XDP program in offload mode(NIC support needed)
   -F, --force		Force install, replacing existing program on interface
   -U, --unload		Unload XDP program instead of loading
   -o, --obj <objname>	Specify the obj filename <objname>, default xdp-drop-kern.o
   -s, --sec <secname>	Specify the section name <secname>, default xdp
   ```

### 总结

这一节以一个简单的程序介绍了XDP程序的两种加载方式，做到真正的从零开始运行XDP程序。

后面的部分会将程序编译过程以Makefile自动化，并继续XDP/eBPF其他特性的介绍和使用。




