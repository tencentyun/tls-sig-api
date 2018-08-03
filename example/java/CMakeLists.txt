find_package(Java REQUIRED COMPONENTS Development)
include(UseJava)
set(CMAKE_JAVA_COMPILE_FLAGS ${CMAKE_JAVA_COMPILE_FLAGS} -encoding UTF-8)
add_jar(Demo
	SOURCES Demo.java
	INCLUDE_JARS tls_sigcheck
	ENTRY_POINT Demo
	)