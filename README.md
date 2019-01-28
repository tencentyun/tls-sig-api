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

## 使用

### 使用默认有效期
```C
#include "tls_signature.h"
#include <string>
#include <iostream>

std::string sig;
int ret = gen_sig(140000000, "xiaojun", priKeyContent, sig);
if (0 != ret) {
	std::cout << "gen_sig failed " << ret << std::endl;
} else {
	std::cout << "gen_sig " << sig << std::endl;
}

```

### 指定有效期
```C
tls_gen_signature_ex2_with_expire
```

### 多线程支持
因为目前默认使用了 openssl，在多线程程序初始化时调用
```C
thread_setup();
```
在程序结束时调用
```C
thread_cleanup();
```

