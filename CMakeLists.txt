cmake_minimum_required(VERSION 3.22.1)
project(cotpy C)

include(GNUInstallDirs)

set(CMAKE_C_STANDARD 17)

set(HEADERS_DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
set(LIBRARY_DESTINATION ${CMAKE_INSTALL_LIBDIR})

set(CMAKE_C_FLAGS "-O3 -fmessage-length=0 -Wall -Werror -Wmissing-prototypes -Wstrict-prototypes -Wpointer-arith -Wwrite-strings")
set(SOURCE_ROOT "src")

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

add_library(cotpy STATIC
        ${SOURCE_ROOT}/cotpy.h
        ${SOURCE_ROOT}/cotpy_types.h
        ${SOURCE_ROOT}/cotpy.c
        src/otpauth.c
        src/otpauth.h
        src/otp.c
        src/otp.h
)

set(PUBLIC_HEADERS
        ${SOURCE_ROOT}/cotpy.h
        ${SOURCE_ROOT}/cotpy_types.h
)

set_target_properties(cotpy PROPERTIES PUBLIC_HEADER "${PUBLIC_HEADERS}")

target_link_libraries(cotpy OpenSSL::Crypto encode uri_encode)

install(
        TARGETS cotpy
        PUBLIC_HEADER DESTINATION ${HEADERS_DESTINATION}
        LIBRARY DESTINATION ${LIBRARY_DESTINATION}
        ARCHIVE DESTINATION ${LIBRARY_DESTINATION}
)
