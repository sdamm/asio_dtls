set(examples_server_sources main.cpp)

add_executable(example_server ${examples_server_sources})
target_link_libraries(example_server asio_dtls)
