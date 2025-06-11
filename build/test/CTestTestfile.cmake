# CMake generated Testfile for 
# Source directory: /home/bulitha/FYP/oqs-provider/test
# Build directory: /home/bulitha/FYP/oqs-provider/build/test
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(oqs_signatures "/home/bulitha/FYP/oqs-provider/build/test/oqs_test_signatures" "oqsprovider" "/home/bulitha/FYP/oqs-provider/test/oqs.cnf")
set_tests_properties(oqs_signatures PROPERTIES  ENVIRONMENT "OPENSSL_MODULES=/home/bulitha/FYP/oqs-provider/build/lib" _BACKTRACE_TRIPLES "/home/bulitha/FYP/oqs-provider/test/CMakeLists.txt;12;add_test;/home/bulitha/FYP/oqs-provider/test/CMakeLists.txt;0;")
add_test(oqs_kems "/home/bulitha/FYP/oqs-provider/build/test/oqs_test_kems" "oqsprovider" "/home/bulitha/FYP/oqs-provider/test/oqs.cnf")
set_tests_properties(oqs_kems PROPERTIES  ENVIRONMENT "OPENSSL_MODULES=/home/bulitha/FYP/oqs-provider/build/lib" _BACKTRACE_TRIPLES "/home/bulitha/FYP/oqs-provider/test/CMakeLists.txt;41;add_test;/home/bulitha/FYP/oqs-provider/test/CMakeLists.txt;0;")
add_test(oqs_libctx "/home/bulitha/FYP/oqs-provider/build/test/oqs_test_libctx" "oqsprovider" "/home/bulitha/FYP/oqs-provider/test/oqs.cnf")
set_tests_properties(oqs_libctx PROPERTIES  ENVIRONMENT "OPENSSL_MODULES=/home/bulitha/FYP/oqs-provider/build/lib" _BACKTRACE_TRIPLES "/home/bulitha/FYP/oqs-provider/test/CMakeLists.txt;62;add_test;/home/bulitha/FYP/oqs-provider/test/CMakeLists.txt;0;")
add_test(oqs_groups "/home/bulitha/FYP/oqs-provider/build/test/oqs_test_groups" "oqsprovider" "/home/bulitha/FYP/oqs-provider/test/oqs.cnf" "/home/bulitha/FYP/oqs-provider/test")
set_tests_properties(oqs_groups PROPERTIES  ENVIRONMENT "OPENSSL_MODULES=/home/bulitha/FYP/oqs-provider/build/lib" _BACKTRACE_TRIPLES "/home/bulitha/FYP/oqs-provider/test/CMakeLists.txt;84;add_test;/home/bulitha/FYP/oqs-provider/test/CMakeLists.txt;0;")
add_test(oqs_tlssig "/home/bulitha/FYP/oqs-provider/build/test/oqs_test_tlssig" "oqsprovider" "/home/bulitha/FYP/oqs-provider/test/openssl-ca.cnf" "/home/bulitha/FYP/oqs-provider/build/test/tmp")
set_tests_properties(oqs_tlssig PROPERTIES  ENVIRONMENT "OPENSSL_MODULES=/home/bulitha/FYP/oqs-provider/build/lib" WORKING_DIRECTORY "/home/bulitha/FYP/oqs-provider/build" _BACKTRACE_TRIPLES "/home/bulitha/FYP/oqs-provider/test/CMakeLists.txt;105;add_test;/home/bulitha/FYP/oqs-provider/test/CMakeLists.txt;0;")
add_test(oqs_endecode "/home/bulitha/FYP/oqs-provider/build/test/oqs_test_endecode" "oqsprovider" "/home/bulitha/FYP/oqs-provider/test/openssl-ca.cnf")
set_tests_properties(oqs_endecode PROPERTIES  ENVIRONMENT "OPENSSL_MODULES=/home/bulitha/FYP/oqs-provider/build/lib" _BACKTRACE_TRIPLES "/home/bulitha/FYP/oqs-provider/test/CMakeLists.txt;129;add_test;/home/bulitha/FYP/oqs-provider/test/CMakeLists.txt;0;")
add_test(oqs_evp_pkey_params "/home/bulitha/FYP/oqs-provider/build/test/oqs_test_evp_pkey_params" "oqsprovider" "/home/bulitha/FYP/oqs-provider/test/openssl-ca.cnf")
set_tests_properties(oqs_evp_pkey_params PROPERTIES  ENVIRONMENT "OPENSSL_MODULES=/home/bulitha/FYP/oqs-provider/build/lib" _BACKTRACE_TRIPLES "/home/bulitha/FYP/oqs-provider/test/CMakeLists.txt;150;add_test;/home/bulitha/FYP/oqs-provider/test/CMakeLists.txt;0;")
