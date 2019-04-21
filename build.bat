set BUILD_TYPE=Release
cd third/zlib-1.2.11
cmake CMakeLists.txt
cmake --build . -- /p:Configuration=%BUILD_TYPE%
cd ../mbedtls
cmake CMakeLists.txt
cmake --build . -- /p:Configuration=%BUILD_TYPE%
cd ../..
cmake CMakeLists.txt
cmake --build . -- /p:Configuration=%BUILD_TYPE%
