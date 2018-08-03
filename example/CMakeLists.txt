include_directories(../src)

add_executable(tls_licence_tools cpp/tls_licence_tools.cpp)
target_link_libraries(tls_licence_tools tlsignature)
install(TARGETS tls_licence_tools
	PERMISSIONS WORLD_READ WORLD_EXECUTE OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_WRITE GROUP_EXECUTE
	DESTINATION bin)

option(BUILD_EXAMPLE_CS "build example for c#" OFF)
if(BUILD_EXAMPLE_CS)
	add_subdirectory(cs)
endif()
option(BUILD_EXAMPLE_JAVA "build example for java" OFF)
if(BUILD_EXAMPLE_JAVA)
	add_subdirectory(java)
endif()
