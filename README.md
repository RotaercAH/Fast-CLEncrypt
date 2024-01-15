# 快速的CL加密库（RUST封装）
论文[《I Want to Ride My BICYCL : BICYCL Implements CryptographY in CLass Groups》](https://link.springer.com/article/10.1007/s00145-023-09459-1)设计了一个更快的[CL加密库](https://gite.lirmm.fr/crypto/bicycl)，其开发语言为C++。为了便于RUST开发者使用此CL加密库，本项目通过RUST FFI的方式封装了C++接口。

- 本项目的定位是一个学习/研究/编程兴趣的项目，仅供学习参考。不对其安全性作出保证。

## 编译c++动态库
```
cd cpp-code/bicycl-master/tests/

g++ -Wall -O2 -fPIC -D_GNU_SOURCE -shared -o libencrypt.so -Wl,-soname=libencrypt.so test_encrypt.cpp -lgmp -lcrypto -lgmpxx

```
## 拷贝c++动态库到rust项目中

```
cp libencrypt.so ../../../rust-ffi/    实际使用中拷贝到自己的rust项目下即可

c++动态库将通过build.rs连接到rust项目，注意替换build.rs中的动态库地址

c++接口调用方式参考main.rs

```

## 目录结构

-cpp-code/bicycl-master:CL加密库，在该库基础上添加了对公钥、密文的序列化与反序列化功能，便于公钥及密文在网络上传输，添加零知识证明
-cpp-code/bicycl-master/tests/test-encrypt.cpp:对CL加密库进行封装，输入输出全部使用字符串，便于rust调用
-rust-ffi/libencrypt.so:编译好的cpp动态库
-rust-ffi/src/cl/clwarpper.rs:封装cpp接口，便于rust调用
-rust-ffi/src/main.rs:示例代码与性能测试
