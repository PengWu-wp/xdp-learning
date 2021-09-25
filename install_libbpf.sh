pushd libbpf/src/
make
sudo make install
cp libbpf.so* /usr/lib/
popd
