# TLSAPI

## 概述
本项目为腾讯云云通信账号体系 tls sig api C++ 实现。

## 下载代码并同步依赖
```shell
git clone https://github.com/tencentyun/tls-sig-api.git
cd tls-sig-api
git submodule update --init --recursive
```

## 构建
构建依赖于 CMake 工具，请予以安装。

### 类 Unix 系统
```shell
cmake CMakeLists.txt
cmake --build .
```

如果需要手动指定 openssl 路径，运行 `cmake CMakeLists.txt` 命令时添加下列命令
```shell
-DOPENSSL_ROOT_DIR=your_openssl_root_dir
```

### Windows
Windows 系统需要安装 VS。

```
cd third/mbedtls
cmake CMakeLists.txt
cmake --build .
cd ../..
cmake CMakeLists.txt
cmake --build .
```

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
因为类 Unix 目前默认使用了 openssl，需要在多线程程序初始化时调用。Windows 版本忽略此问题。
```C
thread_setup();
```
在程序结束时调用
```C
thread_cleanup();
```

