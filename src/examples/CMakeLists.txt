project(examples)

if(asio_dtls_use_boost)
add_subdirectory(boost)
else(asio_dtls_use_boost)
add_subdirectory(asio)
endif(asio_dtls_use_boost)

