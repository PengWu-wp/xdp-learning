pushd libbpf/src/
make
sudo make install
cp {libbpf.so*,libbpf.a}  /usr/lib/
popd
