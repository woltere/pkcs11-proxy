cmake_minimum_required (VERSION 2.8)

if(COMMAND cmake_policy)
      cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)

project (pkcs11 C)

set(PKCS11_PROXY_SRCS gck-rpc-module.c gck-rpc-message.c gck-rpc-util.c egg-buffer.c gck-rpc-tls-psk.c)
set(PKCS11_DAEMON_SRCS egg-buffer.c gck-rpc-daemon-standalone.c gck-rpc-dispatch.c gck-rpc-message.c gck-rpc-util.c syscall-reporter.c syscall-names.h gck-rpc-tls-psk.c)

add_definitions(-Wall)
add_library(pkcs11-proxy SHARED ${PKCS11_PROXY_SRCS})

# Disable console when building Win32 binary in release mode
if (WIN32)
  if("${CMAKE_BUILD_TYPE}" MATCHES "^Rel.*")
    set(GUI_TYPE WIN32)
  endif()
endif()

add_executable (pkcs11-daemon ${GUI_TYPE} ${PKCS11_DAEMON_SRCS})

set_target_properties(pkcs11-proxy PROPERTIES VERSION 0.1 SOVERSION 0)

if (WIN32)
  include_directories("ext/include")

  add_library(dl STATIC IMPORTED)
  set_property(TARGET dl PROPERTY
               IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/ext/lib/libdl.a)
  target_link_libraries (pkcs11-daemon ws2_32)
  target_link_libraries (pkcs11-proxy ws2_32)
endif (WIN32)

target_link_libraries (pkcs11-proxy pthread ssl crypto)
target_link_libraries (pkcs11-daemon dl pthread ssl crypto seccomp)

#install_targets (/lib pkcs11-proxy)
#install_targets (/bin pkcs11-daemon)

install(TARGETS pkcs11-proxy DESTINATION /usr/lib COMPONENT proxy)
install(TARGETS pkcs11-daemon DESTINATION /usr/bin COMPONENT daemon)

add_custom_command(
   OUTPUT syscall-names.h 
   COMMAND ${CMAKE_SOURCE_DIR}/mksyscalls.sh
   WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})


set(CPACK_PACKAGE_VERSION_MAJOR "0")
set(CPACK_PACKAGE_VERSION_MINOR "4")
set(CPACK_PACKAGE_VERSION_PATCH "enovation")
set(CPACK_SYSTEM_NAME, "debian")
set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "woltere@xs4all.nl")
set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
set(CPACK_DEB_COMPONENT_INSTALL 1)
include(CPack)