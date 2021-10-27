# basic 02-parser



# 中文版

这节将以basic01为基础，将XDP程序加载流程自动化，同时将引入eBPF映射的使用；

文件都准备好了，这次把编译都放在了[Makefile](./Makefile)里面，只需make即可得到可执行文件；

映射的定义在[xdp-prog-kern.c](./xdp-prog-kern.c)中，我们使用帮助函数将其pin到了bpf文件系统中；
