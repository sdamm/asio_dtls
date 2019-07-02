set(examples_client_sources main.cpp)

add_executable(example_client ${examples_client_sources})
target_link_libraries(example_client asio_dtls)
