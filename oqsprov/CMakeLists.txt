include(GNUInstallDirs)
execute_process(
  COMMAND git log -1 --format=%h
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE GIT_COMMIT_HASH
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
add_definitions(-DOQSPROVIDER_VERSION_TEXT="${OQSPROVIDER_VERSION_TEXT}")
message(STATUS "Building commit ${GIT_COMMIT_HASH} in ${CMAKE_SOURCE_DIR}")
add_definitions(-DOQS_PROVIDER_COMMIT=" \(${GIT_COMMIT_HASH}\)")

# QKD-specific options (add this here)
option(OQS_ENABLE_QKD "Enable QKD (Quantum Key Distribution) algorithms" OFF)

set(PROVIDER_SOURCE_FILES
  oqsprov.c oqsprov_capabilities.c oqsprov_keys.c
  oqs_kmgmt.c oqs_sig.c oqs_kem.c
  oqs_encode_key2any.c oqs_endecoder_common.c oqs_decode_der2key.c oqsprov_bio.c
  oqsprov.def
)

# Add QKD source files conditionally
if(OQS_ENABLE_QKD)
    list(APPEND PROVIDER_SOURCE_FILES
        oqs_bb84.c
        oqs_qkd_kem.c
        oqsprov_qkd_integration.c
        oqs_qkd_keymgmt.c
    )
    add_compile_definitions(OQS_ENABLE_QKD)
    message(STATUS "QKD Support: Enabled (Pure C implementation)")
else()
    message(STATUS "QKD Support: Disabled")
endif()

set(PROVIDER_HEADER_FILES
  oqs_prov.h oqs_endecoder_local.h
)

# Add QKD header files if enabled
if(OQS_ENABLE_QKD)
    list(APPEND PROVIDER_HEADER_FILES
        oqs_bb84.h
        oqs_qkd_kem.h
    )
endif()

set(OQS_LIBRARY_TYPE MODULE)
if(OQS_PROVIDER_BUILD_STATIC)
  set(OQS_LIBRARY_TYPE STATIC)
endif()

add_library(oqsprovider ${OQS_LIBRARY_TYPE} ${PROVIDER_SOURCE_FILES})

set_target_properties(oqsprovider
    PROPERTIES
    OUTPUT_NAME "oqsprovider"
    PUBLIC_HEADER "oqs_prov.h"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    VERSION ${OQSPROVIDER_VERSION_TEXT}
    SOVERSION 1
    # Compatibility version (-compatibility_version) and current version
    # (-current_version) are not compatible with a `MODULE` library.
    # However, `VERSION` and `SOVERSION` set these two flags.
    # The following two flags remove them.
    MACHO_COMPATIBILITY_VERSION OFF
    MACHO_CURRENT_VERSION OFF
    # For Windows DLLs
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

if (OQS_LIBRARY_TYPE STREQUAL "MODULE")
  # When openssl looks for provider modules it does not prepend "lib" to the
  # provider name.
  set_target_properties(oqsprovider
    PROPERTIES
    PREFIX ""
  )

  if (APPLE)
    # OpenSSL looks for `.dylib` files on XNU-based platforms.
    # Because `MODULE` writes to a `.so` file by default, we must explicitely
    # set the suffix here.
    set_target_properties(oqsprovider
      PROPERTIES
      SUFFIX ".dylib"
    )
  endif()

  if (CYGWIN OR MSVC)
    # OpenSSL looks for `.dll` files on Windows platforms.
    # Because `MODULE` writes to a `.so` file by default, we must explicitely
    # set the suffix here.
    set_target_properties(oqsprovider
      PROPERTIES
      SUFFIX ".dll"
    )
  endif()
endif()

# Original target_link_libraries (keep the PUBLIC keyword style)
target_link_libraries(oqsprovider PUBLIC OQS::oqs ${OPENSSL_CRYPTO_LIBRARY} ${OQS_ADDL_SOCKET_LIBS})

# Add QKD-specific libraries using the same keyword style
if(OQS_ENABLE_QKD)
    # Add math library for BB84 calculations
    find_library(MATH_LIBRARY m)
    if(MATH_LIBRARY)
        target_link_libraries(oqsprovider PUBLIC ${MATH_LIBRARY})
    endif()
    
    # QKD-specific compiler flags
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(oqsprovider PRIVATE
            -fstack-protector-strong
            -D_FORTIFY_SOURCE=2
        )
    endif()
    
    # QKD performance optimizations for C implementation
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        target_compile_options(oqsprovider PRIVATE
            -O3
            -march=native
            -ffast-math  # Safe for BB84 random number generation
        )
    endif()
endif()

install(TARGETS oqsprovider
        LIBRARY DESTINATION "${OPENSSL_MODULES_PATH}"
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/oqs-provider/"
        RUNTIME DESTINATION "${OPENSSL_MODULES_PATH}")

if ("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch64")
  set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE arm64)
elseif("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "x86_64")
  set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE amd64)
endif()

install(TARGETS oqsprovider
        CONFIGURATIONS DebPack
        DESTINATION .
        LIBRARY DESTINATION lib/ossl-modules
        ARCHIVE DESTINATION lib/
        PUBLIC_HEADER DESTINATION include/oqs-provider/
        )

set(CPACK_GENERATOR "DEB")
set(CPACK_PACKAGE_VENDOR "www.openquantumsafe.org")
set(CPACK_PACKAGE_VERSION ${OQSPROVIDER_VERSION_TEXT})
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6, openssl (>= 3.0.0)")
if (NOT "${LIBOQS_LIBRARY_TYPE}" STREQUAL "STATIC_LIBRARY")
  message("Adding liboqs as dynamic dependency for the debian package")
  string(APPEND CPACK_DEBIAN_PACKAGE_DEPENDS ", liboqs (>= 0.8.0)")
endif ()
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "www.openquantumsafe.org")
include(CPack)

if (OQS_PROVIDER_BUILD_STATIC)
  targets_set_static_provider(oqsprovider)
endif()

# Testing for QKD components (add at the end)
if(OQS_ENABLE_QKD AND BUILD_TESTING)
    # QKD unit tests
    add_executable(test_qkd_kem
        test/test_qkd_kem.c
        test/test_bb84.c
    )
    
    # Link to the source files directly, not the MODULE library
    target_link_libraries(test_qkd_kem PUBLIC
        OQS::oqs
        ${OPENSSL_CRYPTO_LIBRARY}
    )
    
    if(MATH_LIBRARY)
        target_link_libraries(test_qkd_kem PUBLIC ${MATH_LIBRARY})
    endif()
    
    target_include_directories(test_qkd_kem PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${OPENSSL_INCLUDE_DIR}
    )
    
    # Add QKD tests to CTest
    add_test(NAME qkd_kem_test COMMAND test_qkd_kem)
    add_test(NAME bb84_protocol_test COMMAND test_qkd_kem --bb84-only)
    
endif()