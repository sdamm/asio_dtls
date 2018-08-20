cmake_minimum_required (VERSION 3.2)
project(asio_dtls)

find_program(
  CLANG_TIDY_EXE
  NAMES "clang-tidy"
  DOC "Path to clang-tidy executable"
  )
if(NOT CLANG_TIDY_EXE)
  message(STATUS "clang-tidy not found.")
else()
  message(STATUS "clang-tidy found: ${CLANG_TIDY_EXE}")
  set(DO_CLANG_TIDY "${CLANG_TIDY_EXE}" "-checks=*,-fuchsia-*,-google-runtime-references")

  set(CMAKE_CXX_CLANG_TIDY ${DO_CLANG_TIDY})
endif()

find_package(OpenSSL REQUIRED)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads)

set(asio_header_dir "" CACHE PATH "Path to the asio library used.")
add_library(asio INTERFACE)
target_include_directories(asio INTERFACE asio_header_dir)

add_library(asio_dtls INTERFACE)
target_include_directories(asio_dtls INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_definitions(asio_dtls INTERFACE ASIO_HEADER_ONLY)
target_link_libraries(asio_dtls INTERFACE OpenSSL::SSL OpenSSL::Crypto Threads::Threads)

set(asio_dtls_sources
    include/asio/ssl/dtls/impl/context.ipp
    include/asio/ssl/dtls/detail/impl/engine.ipp)

set(ASIO_DTLS_PUBLIC_HEADERS
    asio/dtls.hpp
    asio/ssl/dtls/acceptor.hpp
    asio/ssl/dtls/context.hpp
    asio/ssl/dtls/default_cookie_generator.hpp
    )

option(asio_build_dtls_static "Use asio and asio_dtls header only" OFF)
if(asio_build_dtls_static)
  add_library(asio_dtls_static STATIC)
  target_include_directories(asio_dtls ${CMAKE_CURRENT_SOURCE_DIR}/include)
  target_link_libraries(asio_dtls_static OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
endif(asio_build_dtls_static)

option(asio_build_dtls_shared "Use asio and asio_dtls header only" OFF)
if(asio_build_dtls_shared)
  add_library(asio_dtls_shared )
  target_include_directories(asio_dtls ${CMAKE_CURRENT_SOURCE_DIR}/include)
  target_link_libraries(asio_dtls_shared OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
endif(asio_build_dtls_shared)

add_subdirectory(src)
