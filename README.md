# TLSAPI

## ����

example ������ʽ�ӿڵ�ʹ�� demo��

src �����˱��������ʽ�ӿڵ�Դ�ļ��������� java����

java ������ java ���ԵĽӿڴ��롣����tls_sigcheck.java��jni�Ľӿ�

����openssl��zlib����������gtest

## ����

ʹ��cmake����

```shell
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX={install_path}
make install
```

������ɺ����install_path�п������ֽ��

### cmakeѡ��

* BUILD_JAVA=ON ����java�� ��Ҫ����JAVA_HOME��������
* BUILD_JNI=ON ����jni��so ��Ҫ����JAVA_HOME��������
* BUILD_EXAMPLE_JAVA=ON ����java example ��Ҫ����JAVA_HOME��������
* BUILD_EXAMPLE_CS=ON ��Ҫ��װc#������