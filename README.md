# TLSAPI

## 概述

example 各种形式接口的使用 demo。

src 包含了编译各种形式接口的源文件（不包括 java）。

java 包含了 java 语言的接口代码。其中tls_sigcheck.java是jni的接口

依赖openssl、zlib，测试依赖gtest

## 下载代码与依赖
```shell
git clone https://github.com/tencentyun/tls-sig-api.git
cd tls-sig-api
git submodule update --init --recursive
```

## 构建

使用cmake构建

```shell
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX={install_path}
make install
```

如果需要手动指定 openssl 路径，运行 cmake 命令时添加下列命令
```shell
-DOPENSSL_ROOT_DIR=your_openssl_root_dir
```

构建完成后可在install_path中看到各种结果

### cmake选项

* BUILD_EXAMPLE_CS=ON 需要安装c#编译器