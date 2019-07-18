# TLSAPI

## 概述
本项目为腾讯云云通信账号体系 tls sig api C++ 实现。

## 下载代码并同步依赖
```shell
git clone https://github.com/tencentyun/tls-sig-api.git
cd tls-sig-api
git submodule update --init --recursive
```

如果上面同步代码的操作出现问题，可以到[这里](https://github.com/tencentyun/tls-sig-api/releases)下载源代码。

## 构建

### 类 Unix 系统
构建依赖于 `CMake` 、 `make` 以及 `gcc`，请确保已经安装。

```shell
cmake CMakeLists.txt
cmake --build .
```

如果需要手动指定 openssl 路径，运行 `cmake CMakeLists.txt` 命令时添加下列命令
```shell
cmake  -DOPENSSL_ROOT_DIR=your_openssl_root_dir CMakeLists.txt
cmake --build .
```

头文件路径如下
```
src/tls_signature.h
```

库文件路径如下
```

./libtlsignature.a
```

用户构建项目时除了链接 `libtlsignature.a`，还需引入 `zlib` 和 `openssl` 加密算法库，类 Unix 系统一般都会自带，只需要在链接指令中添加下面的指令
```
-lz -lcrypto
```

### Windows
Windows 平台构建依赖 `CMake` 和 `Visual Studio`，请确保已经安装。

```
.\build.bat
```

头文件路径如下

```
src/tls_signature.h
```

库文件路径，分 Win32 和 x64，而且 Debug 和 Release 也通过目录予以区分
```
tls-sig-api_xx/xxxx/tlsignature.lib
tls-sig-api_xx/xxxx/zlibstatic.lib
tls-sig-api_xx/xxxx/mbedcrypto.lib
```
另外 Debug 版本的 zlib 名称为 zlibstaticd.lib

用户构建项目时只需要引用头文件 `src/tls_signature.h` 和上述三个库文件。

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
因为类 Unix 目前默认使用了 openssl，需要在多线程程序初始化时调用。windows 版本无此问题。
```C
thread_setup();
```
在程序结束时调用
```C
thread_cleanup();
```

