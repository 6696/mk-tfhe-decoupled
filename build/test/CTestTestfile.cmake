# CMake generated Testfile for 
# Source directory: /home/daniil/IdeaProjects/mk-tfhe-auction/src/test
# Build directory: /home/daniil/IdeaProjects/mk-tfhe-auction/build/test
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(unittests-spqlios-avx "unittests-spqlios-avx")
set_tests_properties(unittests-spqlios-avx PROPERTIES  _BACKTRACE_TRIPLES "/home/daniil/IdeaProjects/mk-tfhe-auction/src/test/CMakeLists.txt;69;add_test;/home/daniil/IdeaProjects/mk-tfhe-auction/src/test/CMakeLists.txt;0;")
add_test(unittests-spqlios-fma "unittests-spqlios-fma")
set_tests_properties(unittests-spqlios-fma PROPERTIES  _BACKTRACE_TRIPLES "/home/daniil/IdeaProjects/mk-tfhe-auction/src/test/CMakeLists.txt;69;add_test;/home/daniil/IdeaProjects/mk-tfhe-auction/src/test/CMakeLists.txt;0;")
subdirs("googletest")
