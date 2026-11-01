cmake_minimum_required(VERSION 3.15)
project(novanative C)

set(CMAKE_C_STANDARD 11)

# BUILD_SECRET: số 32-bit (hex) phải khớp với setting "NativeStringEncrypt.BuildSecret"
# bên Grunt khi obfuscate. Luôn truyền riêng, KHÔNG commit secret thật vào repo public:
#   cmake -DBUILD_SECRET=0x1A2B3C4D ..
if(NOT DEFINED BUILD_SECRET)
    set(BUILD_SECRET 0x0)
    message(WARNING "BUILD_SECRET chưa được set, dùng 0x0 (KHÔNG an toàn cho bản release thật).")
endif()

find_package(JNI REQUIRED)

add_library(novanative SHARED src/stringdecrypt.c)

target_include_directories(novanative PRIVATE ${JNI_INCLUDE_DIRS})
target_compile_definitions(novanative PRIVATE BUILD_SECRET=${BUILD_SECRET})

# Đặt tên output rõ ràng theo platform để workflow dễ gom file lại:
#   Windows -> novanative.dll      -> đổi tên thành win-x64.bin
#   Linux   -> libnovanative.so    -> đổi tên thành linux-x64.bin
#   macOS   -> libnovanative.dylib -> đổi tên thành mac-x64.bin / mac-arm64.bin
set_target_properties(novanative PROPERTIES
    PREFIX ""
    OUTPUT_NAME "novanative"
)

if(APPLE)
    set_target_properties(novanative PROPERTIES SUFFIX ".dylib")
elseif(WIN32)
    set_target_properties(novanative PROPERTIES SUFFIX ".dll")
else()
    set_target_properties(novanative PROPERTIES SUFFIX ".so")
endif()
