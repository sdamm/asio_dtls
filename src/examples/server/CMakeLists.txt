set(examples_server_sources main.cpp)


find_program(
  OPENSSL_EXE
  NAMES "openssl"
  DOC "Path to openssl executable"
  )
# Generate certificates for example server
if(OPENSSL_EXE)
    add_custom_command(
        OUTPUT privkey.pem cert.pem
        COMMAND ${OPENSSL_EXE} genrsa -out privkey.pem
        COMMAND ${OPENSSL_EXE} req -new -x509 -key privkey.pem -out cert.pem -days 365 -subj "/C=DE/ST=Germyny/L=Balingen/O=Demo/OU=Testing/CN=localhost.localdomain"
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
    set(examples_server_sources ${examples_server_sources} privkey.pem cert.pem)
else(OPESSL_EXE)
    message(WARNING "No openssl binary found not generating demo certificates for examples.")
endif(OPENSSL_EXE)

add_executable(example_server ${examples_server_sources})
target_link_libraries(example_server asio_dtls)
