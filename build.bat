del CMakeCache.txt /f /s /q /a
set ARCH=Win32
set BUILD_TYPE=Release
cd third/zlib-1.2.11
cmake -A %ARCH% CMakeLists.txt
cmake --build . -- /p:Configuration=%BUILD_TYPE%
cd ../mbedtls
cmake -A %ARCH% CMakeLists.txt
cmake --build . -- /p:Configuration=%BUILD_TYPE%
cd ../..
cmake -A %ARCH% -DCMAKE_BUILD_TYPE:STRING=%BUILD_TYPE% CMakeLists.txt
cmake --build . -- /p:Configuration=%BUILD_TYPE%
