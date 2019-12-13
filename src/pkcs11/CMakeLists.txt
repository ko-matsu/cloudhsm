cmake_minimum_required(VERSION 3.1)
option(ENABLE_SHARED "enable shared library (ON or OFF. default:OFF)" OFF)

project(cloudhsmpkcs11 C)

if(ENABLE_SHARED)
add_library(${PROJECT_NAME} SHARED)
else()
add_library(${PROJECT_NAME} STATIC)
endif()

target_sources(${PROJECT_NAME}
  PRIVATE
    common.c pkcs11.c common.h ec_sign.c sign.h
)
target_link_libraries(${PROJECT_NAME} dl)
