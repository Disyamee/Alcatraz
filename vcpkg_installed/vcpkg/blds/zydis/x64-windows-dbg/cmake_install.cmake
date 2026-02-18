# Install script for directory: C:/Users/Deniska/Downloads/Alcatraz-master/Alcatraz-master/vcpkg_installed/vcpkg/blds/zydis/src/v4.1.0-1fdb2423e4.clean

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "C:/Users/Deniska/Downloads/Alcatraz-master/Alcatraz-master/vcpkg_installed/vcpkg/pkgs/zydis_x64-windows/debug")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Debug")
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

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "OFF")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/zydis" TYPE FILE FILES
    "C:/Users/Deniska/Downloads/Alcatraz-master/Alcatraz-master/vcpkg_installed/vcpkg/blds/zydis/x64-windows-dbg/zydis-config.cmake"
    "C:/Users/Deniska/Downloads/Alcatraz-master/Alcatraz-master/vcpkg_installed/vcpkg/blds/zydis/x64-windows-dbg/zydis-config-version.cmake"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY OPTIONAL FILES "C:/Users/Deniska/Downloads/Alcatraz-master/Alcatraz-master/vcpkg_installed/vcpkg/blds/zydis/x64-windows-dbg/Zydis.lib")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE SHARED_LIBRARY FILES "C:/Users/Deniska/Downloads/Alcatraz-master/Alcatraz-master/vcpkg_installed/vcpkg/blds/zydis/x64-windows-dbg/Zydis.dll")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/zydis/zydis-targets.cmake")
    file(DIFFERENT _cmake_export_file_changed FILES
         "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/zydis/zydis-targets.cmake"
         "C:/Users/Deniska/Downloads/Alcatraz-master/Alcatraz-master/vcpkg_installed/vcpkg/blds/zydis/x64-windows-dbg/CMakeFiles/Export/c520ad4c175752a05a118ad881557759/zydis-targets.cmake")
    if(_cmake_export_file_changed)
      file(GLOB _cmake_old_config_files "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/zydis/zydis-targets-*.cmake")
      if(_cmake_old_config_files)
        string(REPLACE ";" ", " _cmake_old_config_files_text "${_cmake_old_config_files}")
        message(STATUS "Old export file \"$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/zydis/zydis-targets.cmake\" will be replaced.  Removing files [${_cmake_old_config_files_text}].")
        unset(_cmake_old_config_files_text)
        file(REMOVE ${_cmake_old_config_files})
      endif()
      unset(_cmake_old_config_files)
    endif()
    unset(_cmake_export_file_changed)
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/zydis" TYPE FILE FILES "C:/Users/Deniska/Downloads/Alcatraz-master/Alcatraz-master/vcpkg_installed/vcpkg/blds/zydis/x64-windows-dbg/CMakeFiles/Export/c520ad4c175752a05a118ad881557759/zydis-targets.cmake")
  if(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/zydis" TYPE FILE FILES "C:/Users/Deniska/Downloads/Alcatraz-master/Alcatraz-master/vcpkg_installed/vcpkg/blds/zydis/x64-windows-dbg/CMakeFiles/Export/c520ad4c175752a05a118ad881557759/zydis-targets-debug.cmake")
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include" TYPE DIRECTORY FILES "C:/Users/Deniska/Downloads/Alcatraz-master/Alcatraz-master/vcpkg_installed/vcpkg/blds/zydis/src/v4.1.0-1fdb2423e4.clean/include/")
endif()

if(CMAKE_INSTALL_COMPONENT)
  set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
file(WRITE "C:/Users/Deniska/Downloads/Alcatraz-master/Alcatraz-master/vcpkg_installed/vcpkg/blds/zydis/x64-windows-dbg/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
