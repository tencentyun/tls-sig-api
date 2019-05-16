set ARCH=Win32
set BUILD_TYPE=Release
set ZLIB=zlib-1.2.11
set MBEDTLS=mbedtls

del CMakeCache.txt /f /s /q /a

cd third\%ZLIB%
cmake -A %ARCH% CMakeLists.txt
cmake --build . -- /p:Configuration=%BUILD_TYPE%

cd ../%MBEDTLS%
cmake -A %ARCH% CMakeLists.txt
cmake --build . -- /p:Configuration=%BUILD_TYPE%

cd ../..
cmake -A %ARCH% -DCMAKE_BUILD_TYPE:STRING=%BUILD_TYPE% CMakeLists.txt
cmake --build . -- /p:Configuration=%BUILD_TYPE%

set PREBUILD_DIR=tls-sig-api_%ARCH%
mkdir %PREBUILD_DIR%\%BUILD_TYPE%
xcopy %BUILD_TYPE%\* %PREBUILD_DIR%\%BUILD_TYPE% /E /Y
xcopy third\%ZLIB%\%BUILD_TYPE%\* %PREBUILD_DIR%\%BUILD_TYPE% /E /Y
xcopy third\%MBEDTLS%\library\%BUILD_TYPE%\* %PREBUILD_DIR%\%BUILD_TYPE% /E /Y