set(examples_boost_async_client_headers client.h)
set(examples_boost_async_client_sources main.cpp client.cpp)

add_executable(example_boost_async_client ${examples_boost_async_client_sources})
target_link_libraries(example_boost_async_client asio_dtls Boost::system)
