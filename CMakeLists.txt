cmake_minimum_required(VERSION 2.8)

project("Parse Certificate")

set(OPENSSL_PATH ${CMAKE_SOURCE_DIR}/openssl)

include_directories(${OPENSSL_PATH}/include)

add_executable(parse_cert
	src/main.cpp
	src/parse.cpp
)

if(UNIX)
	find_package(OpenSSL 1.0 REQUIRED)
else()
	list(APPEND OPENSSL_LIBRARIES ${OPENSSL_PATH}/lib/libeay32${CMAKE_STATIC_LIBRARY_SUFFIX})
	list(APPEND OPENSSL_LIBRARIES ${OPENSSL_PATH}/lib/ssleay32${CMAKE_STATIC_LIBRARY_SUFFIX})
endif()

target_link_libraries(parse_cert ${OPENSSL_LIBRARIES})
