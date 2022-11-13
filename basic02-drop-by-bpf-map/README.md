# basic02

这节将以basic01为基础，引入eBPF映射；

文件都准备好了，只需make即可得到可执行文件；

## 涉及内容

### eBPF map

eBPF map（映射）是一个通用的数据结构存储不同类型的数据，提供了用户态和内核态数据交互、数据存储、多程序共享数据等功能。

它以键/值的形式保存在内核中，可以保存事先指定大小的任何类型的数据，可被任意BPF程序访问，用户空间的程序也可以通过文件描述符访问BPF映射。

### 创建eBPF map

最直接的方式是通过bpf系统调用，将系统调用第一个参数设置为`BPF_MAP_CREATE`表示创建一个新的映射，返回映射的文件描述符。

libbpf中也有封装该系统调用的函数：`bpf_map_create`。

另外还有一种可读性更高的方式是用ELF约定来创建映射，底层依然是用bpf系统调用，本例中使用该种方式，映射的预定义在[xdp_prog_kern.c](./xdp_prog_kern.c)中。

> 注：
>
> 根据[Libbpf: the road to v1.0文档](https://docs.google.com/document/d/1UyjTZuPFWiPFyKk1tV5an11_iaRuec6U-ZESZ54nNTY/edit#)：
>
> 旧版libbpf中用`struct bpf_map_def`和`SEC("maps")`方式预定义map的方式在libbpf v1.0+已经不能用了，从libbpf V1.0开始，将只支持BTF定义的映射。
>
> 也就是说，以往：
>
> ```c
> struct bpf_map_def SEC("maps") btf_map = {
>         .type = BPF_MAP_TYPE_ARRAY,
>         .max_entries = 4,
>         .key_size = sizeof(int),
>         .value_size = sizeof(struct ipv_counts),
> };
> ```
>
> 这种形式的预定义不再支持，需要用以下这种形式代替：
>
> ```c
> struct {
>     __uint(type, BPF_MAP_TYPE_ARRAY);
>     __uint(max_entries, 4);
>     __type(key, int);
>     __type(value, struct ipv_counts);
> } btf_map SEC(".maps");
> ```

### BPF虚拟文件系统

为了让BPF映射能够在程序结束后保留在内存中，并且能够在不同程序之间交互，BPF提供了用以固定和获取来自虚拟文件系统的映射和BPF程序的系统调用，即`BPF_PIN_FD`和`BPF_OBJ_GET`。

BPF虚拟文件系统的默认目录是`/sys/fs/bpf`，如果内核不支持BPF，默认不会挂载该文件系统，可以通过mount来挂载：

```bash
mount -t bpf bpf /sys/fs/bpf/
```

libbpf也提供了对这两种系统调用的封装：`bpf_obj_pin`和`bpf_obj_get`；

## 程序

如果装好了依赖软件，更新好了submodule，正常来说make即可；

BPF映射的更新和程序的加载/卸载集合在了同一文件中，以下是使用方法。

```bash
usage ./xdp_prog_user [options]

Requried options:
-d, --dev <ifname>              Specify the device <ifname>

Other options:
-h, --help              this text you see right here
-S, --skb-mode          Install XDP program in SKB (AKA generic) mode
-N, --native-mode       (default) Install XDP program in native mode
-H, --offload-mode      Install XDP program in offload (AKA HW) mode(NIC support needed)
-F, --force             Force install, replacing existing program on interface
-U, --unload            Unload XDP program instead of loading
-o, --obj <objname>     Specify the obj filename <objname>
-n, --name <progname>   Specify the program name <progname>
Map operations:
    --map-add <addr>    Add an IP to blacklist_map
    --map-delete <addr/all>     Delete an IP to blacklist_map
    --map-show          Show blocked IPs in blacklist_map

```

本例使用了哈希类型映射，以键存储IPv4地址，当收到数据包的源地址在映射内时，就会通过`XDP_DROP`丢弃；

很简单的例子……



