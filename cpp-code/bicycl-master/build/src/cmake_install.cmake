# Install script for directory: /home/xlong/rust-to-cpp/cpp-code/bicycl-master/src

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Release")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include" TYPE FILE FILES "/home/xlong/rust-to-cpp/cpp-code/bicycl-master/src/bicycl.hpp")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/bicycl" TYPE FILE FILES
    "/home/xlong/rust-to-cpp/cpp-code/bicycl-master/src/bicycl/seclevel.hpp"
    "/home/xlong/rust-to-cpp/cpp-code/bicycl-master/src/bicycl/seclevel.inl"
    "/home/xlong/rust-to-cpp/cpp-code/bicycl-master/src/bicycl/gmp_extras.hpp"
    "/home/xlong/rust-to-cpp/cpp-code/bicycl-master/src/bicycl/gmp_extras.inl"
    "/home/xlong/rust-to-cpp/cpp-code/bicycl-master/src/bicycl/openssl_wrapper.hpp"
    "/home/xlong/rust-to-cpp/cpp-code/bicycl-master/src/bicycl/openssl_wrapper.inl"
    "/home/xlong/rust-to-cpp/cpp-code/bicycl-master/src/bicycl/ec.hpp"
    "/home/xlong/rust-to-cpp/cpp-code/bicycl-master/src/bicycl/ec.inl"
    "/home/xlong/rust-to-cpp/cpp-code/bicycl-master/src/bicycl/qfi.hpp"
    "/home/xlong/rust-to-cpp/cpp-code/bicycl-master/src/bicycl/qfi.inl"
    "/home/xlong/rust-to-cpp/cpp-code/bicycl-master/src/bicycl/CL_HSM_utils.hpp"
    "/home/xlong/rust-to-cpp/cpp-code/bicycl-master/src/bicycl/CL_HSM_utils.inl"
    "/home/xlong/rust-to-cpp/cpp-code/bicycl-master/src/bicycl/CL_HSMqk.hpp"
    "/home/xlong/rust-to-cpp/cpp-code/bicycl-master/src/bicycl/CL_HSMqk.inl"
    "/home/xlong/rust-to-cpp/cpp-code/bicycl-master/src/bicycl/CL_HSM2k.hpp"
    "/home/xlong/rust-to-cpp/cpp-code/bicycl-master/src/bicycl/CL_HSM2k.inl"
    "/home/xlong/rust-to-cpp/cpp-code/bicycl-master/src/bicycl/Paillier.hpp"
    "/home/xlong/rust-to-cpp/cpp-code/bicycl-master/src/bicycl/Paillier.inl"
    "/home/xlong/rust-to-cpp/cpp-code/bicycl-master/src/bicycl/Joye_Libert.hpp"
    "/home/xlong/rust-to-cpp/cpp-code/bicycl-master/src/bicycl/Joye_Libert.inl"
    "/home/xlong/rust-to-cpp/cpp-code/bicycl-master/src/bicycl/threshold_ECDSA.hpp"
    "/home/xlong/rust-to-cpp/cpp-code/bicycl-master/src/bicycl/threshold_ECDSA.inl"
    )
endif()

