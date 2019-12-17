cmake_minimum_required(VERSION 3.13)
project(aws-cloudhsm-pkcs11-examples)

SET(ORGANIZATION_NAME "Crypto Garage, Inc.")
SET(CMAKE_C_FLAGS "-Wall -Werror -Wno-pointer-sign -fno-signed-char -std=c99")

# ENABLE_TESTING()

include_directories(include/pkcs11/v2.40)
include_directories(src/pkcs11)

add_subdirectory(src/pkcs11)
