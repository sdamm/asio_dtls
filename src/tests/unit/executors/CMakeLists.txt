add_library(test_executors STATIC executor.cpp)
target_link_libraries(test_executors asio_dtls)
