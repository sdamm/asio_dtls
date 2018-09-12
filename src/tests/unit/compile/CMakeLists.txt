add_library(test_compile STATIC compile.cpp)
target_link_libraries(test_compile asio_dtls)
