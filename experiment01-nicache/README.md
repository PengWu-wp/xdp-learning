# experiment01-nicache



# 中文版

处于实验阶段的程序，是NICACHE的一个demo，验证SmartNIC卸载缓存处理的可能，应用
使用了Memcached，通信采用UDP，智能网卡使用了Netronome的CX系列25G网卡。

依赖的软件：

```bash
sudo apt install -y gpg curl tar make gcc flex bison libssl-dev libelf-dev clang-9 llvm-9
```

以及需要下载内核源码：

```bash
./kernel-src-download.sh
./kernel-src-prepare.sh
```

之后make编译后测试即可。
