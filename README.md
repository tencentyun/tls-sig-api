# TLSAPI

## 概述

example 各种形式接口的使用 demo。

src 包含了编译各种形式接口的源文件（不包括 java）。

java 包含了 java 语言的接口代码。其中tls_sigcheck.java是jni的接口

依赖openssl、zlib，测试依赖gtest

## 构建

使用cmake构建

```shell
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX={install_path}
make install
```

构建完成后可在install_path中看到各种结果

### cmake选项

* BUILD_JAVA=ON 构建java包 需要设置JAVA_HOME环境变量
* BUILD_JNI=ON 构建jni的so 需要设置JAVA_HOME环境变量
* BUILD_EXAMPLE_JAVA=ON 构建java example 需要设置JAVA_HOME环境变量
* BUILD_EXAMPLE_CS=ON 需要安装c#编译器