# This tests all Public headers for selfcontainment
#
# Selfcontinment is compiletime only, so they are not added to the runtime tests

foreach(header ${ASIO_DTLS_PUBLIC_HEADERS})
    string(REPLACE "/" "_" header_friendly ${header})
    string(REPLACE "." "_" header_friendly_ext ${header_friendly})

    set(testsource ${CMAKE_CURRENT_BINARY_DIR}/${header_friendly_ext}.cpp)
    configure_file(selfcontaincheck.cpp ${testsource})

    set(test_target_name test_${header_friendly_ext}_selfcontained_check)
    add_executable(${test_target_name} ${testsource})
    target_link_libraries(${test_target_name} asio_dtls)
endforeach(header)
