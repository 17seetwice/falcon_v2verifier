cmake_minimum_required(VERSION 3.10)

project(falcon_sim)

set(SOURCE_FILES
    src/main.cpp
    src/Vehicle.cpp
    src/v2vcrypto.cpp
    src/bsm.cpp
)

add_executable(${PROJECT_NAME} ${SOURCE_FILES})

target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(${PROJECT_NAME} PRIVATE $ENV{HOME}/liboqs-x86/include)

find_package(Threads REQUIRED)

target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::Crypto $ENV{HOME}/liboqs-x86/lib/liboqs.a Threads::Threads)
