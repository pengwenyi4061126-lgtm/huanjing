cmake_minimum_required(VERSION 3.20)
project(CacNativeBridge LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_library(NativeBridge SHARED
    NativeBridge/Identity.cpp
    NativeBridge/Audit.cpp
    NativeBridge/HookEngine.cpp
    NativeBridge/Firmware.cpp
    NativeBridge/ApiHooks.cpp
    NativeBridge/ChildInject.cpp
    NativeBridge/WmiHooks.cpp
    NativeBridge/NetworkHooks.cpp
    NativeBridge/NativeBridge.cpp
)
target_compile_definitions(NativeBridge PRIVATE _WIN32_WINNT=0x0A00 WIN32_LEAN_AND_MEAN UNICODE _UNICODE)
target_compile_options(NativeBridge PRIVATE /guard:cf)
target_link_options(NativeBridge PRIVATE /guard:cf)
target_link_libraries(NativeBridge PRIVATE iphlpapi bcrypt wbemuuid ole32 oleaut32)

add_executable(cac-native-launch Launcher/main.cpp)
target_compile_definitions(cac-native-launch PRIVATE _WIN32_WINNT=0x0A00 WIN32_LEAN_AND_MEAN UNICODE _UNICODE)
target_include_directories(cac-native-launch PRIVATE "${CMAKE_SOURCE_DIR}/obj")
target_link_libraries(cac-native-launch PRIVATE bcrypt)

set_target_properties(NativeBridge cac-native-launch PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/dist"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/dist"
)
