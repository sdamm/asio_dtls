set(examples_async_client_headers client.h)
set(examples_async_client_sources main.cpp client.cpp)

add_executable(example_async_client ${examples_async_client_sources})
target_link_libraries(example_async_client asio_dtls)
