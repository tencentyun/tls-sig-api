cmake_minimum_required(VERSION 2.8)
project(tls_sig_api)

find_package(ZLIB REQUIRED)
find_package(OpenSSL REQUIRED)
if(UNIX)
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()
if(MSVC)
    option(BUILD_STATIC_VCRUNTIME "static link vc runtime" OFF)
    set(CompilerFlags
        CMAKE_CXX_FLAGS
        CMAKE_CXX_FLAGS_DEBUG
        CMAKE_CXX_FLAGS_RELEASE
        CMAKE_C_FLAGS
        CMAKE_C_FLAGS_DEBUG
        CMAKE_C_FLAGS_RELEASE
        )
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /D_SILENCE_TR1_NAMESPACE_DEPRECATION_WARNING")
    add_definitions(/wd"4819")
    foreach(CompilerFlag ${CompilerFlags})
        if (BUILD_STATIC_VCRUNTIME)
            string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
        else()
            string(REPLACE "/MT" "/MD" ${CompilerFlag} "${${CompilerFlag}}")
        endif()
    endforeach()
endif()

include_directories(
    third/rapidjson/include
    third/fmt/include
    ${ZLIB_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    )
add_definitions(-DFMT_HEADER_ONLY -DRAPIDJSON_HAS_STDSTRING=1 -DUSE_OPENSSL)

option(BUILD_SHARED "build tlsignature shared library" OFF)
if(BUILD_SHARED)
    add_library(tlsignature SHARED src/tls_signature.cpp)
else()
    add_library(tlsignature src/tls_signature.cpp)
endif()
target_link_libraries(tlsignature
    ZLIB::ZLIB
    OpenSSL::Crypto
)

add_executable(signature src/signature.cpp)
target_link_libraries(signature tlsignature)

add_library(sigcheck SHARED src/sigcheck.cpp)
target_link_libraries(sigcheck tlsignature)

option(BUILD_JNI "build jni dynamic library" OFF)
if(BUILD_JNI)
	find_package(JNI REQUIRED)
	include_directories(${JNI_INCLUDE_DIRS})
	add_library(jnisigcheck SHARED src/com_tls_sigcheck_tls_sigcheck.cpp)
	target_link_libraries(jnisigcheck tlsignature)
	install(TARGETS jnisigcheck
		PERMISSIONS WORLD_READ WORLD_EXECUTE OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_WRITE GROUP_EXECUTE
		DESTINATION lib)
endif()

option(BUILD_JAVA "build java jni api" OFF)
if(BUILD_JAVA)
    set(CMAKE_JAVA_TARGET_OUTPUT_DIR ${CMAKE_INSTALL_PREFIX}/lib)
	find_package(Java REQUIRED COMPONENTS Development)
	include(UseJava)
	set(CMAKE_JAVA_COMPILE_FLAGS ${CMAKE_JAVA_COMPILE_FLAGS} -encoding UTF-8)
	add_jar(tls_sigcheck java/com/tls/sigcheck/tls_sigcheck.java)
endif()

option(BUILD_EXAMPLE "build example" ON)
if(BUILD_EXAMPLE)
	add_subdirectory(example)
endif()

option(BUILD_TEST "build testcase" OFF)
if(BUILD_TEST)
    enable_testing()
    find_package(GTest REQUIRED)
    include_directories(${PROJECT_SOURCE_DIR}/src)
    add_executable(unit_tests test/unit_test.cpp)
    target_link_libraries(unit_tests PRIVATE GTest::GTest GTest::Main 
    ZLIB::ZLIB
    OpenSSL::Crypto)
    add_test(unit_tests unit_tests)
endif()


install(TARGETS tlsignature
	PERMISSIONS WORLD_READ OWNER_READ OWNER_WRITE GROUP_READ GROUP_WRITE
	DESTINATION lib)
install(TARGETS sigcheck
	PERMISSIONS WORLD_READ WORLD_EXECUTE OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_WRITE GROUP_EXECUTE
	DESTINATION lib)
install(TARGETS signature tlsignature
	PERMISSIONS WORLD_READ WORLD_EXECUTE OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_WRITE GROUP_EXECUTE
	DESTINATION bin)
install(FILES src/tls_signature.h src/sigcheck.h
	PERMISSIONS WORLD_READ OWNER_READ OWNER_WRITE GROUP_READ GROUP_WRITE
	DESTINATION include)
