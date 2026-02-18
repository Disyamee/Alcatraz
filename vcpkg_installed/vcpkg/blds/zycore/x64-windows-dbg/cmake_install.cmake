# Install script for directory: C:/Users/Deniska/Downloads/Alcatraz-master/Alcatraz-master/vcpkg_installed/vcpkg/blds/zycore/src/v1.5.0-7af075296a.clean

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "C:/Users/Deniska/Downloads/Alcatraz-master/Alcatraz-master/vcpkg_installed/vcpkg/pkgs/zycore_x64-windows/debug")
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
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/zycore" TYPE FILE FILES
    "C:/Users/Deniska/Downloads/Alcatraz-master/Alcatraz-master/vcpkg_installed/vcpkg/blds/zycore/src/v1.5.0-7af075296a.clean/cmake/zyan-functions.cmake"
    "C:/Users/Deniska/Downloads/Alcatraz-master/Alcatraz-master/vcpkg_installed/vcpkg/blds/zycore/x64-windows-dbg/zycore-config.cmake"
    "C:/Users/Deniska/Downloads/Alcatraz-master/Alcatraz-master/vcpkg_installed/vcpkg/blds/zycore/x64-windows-dbg/zycore-config-version.cmake"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY OPTIONAL FILES "C:/Users/Deniska/Downloads/Alcatraz-master/Alcatraz-master/vcpkg_installed/vcpkg/blds/zycore/x64-windows-dbg/Zycore.lib")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE SHARED_LIBRARY FILES "C:/Users/Deniska/Downloads/Alcatraz-master/Alcatraz-master/vcpkg_installed/vcpkg/blds/zycore/x64-windows-dbg/Zycore.dll")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/zycore/zycore-targets.cmake")
    file(DIFFERENT _cmake_export_file_changed FILES
         "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/zycore/zycore-targets.cmake"
         "C:/Users/Deniska/Downloads/Alcatraz-master/Alcatraz-master/vcpkg_installed/vcpkg/blds/zycore/x64-windows-dbg/CMakeFiles/Export/be8fb0d055ecad19586b2bae767d49d8/zycore-targets.cmake")
    if(_cmake_export_file_changed)
      file(GLOB _cmake_old_config_files "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/zycore/zycore-targets-*.cmake")
      if(_cmake_old_config_files)
        string(REPLACE ";" ", " _cmake_old_config_files_text "${_cmake_old_config_files}")
        message(STATUS "Old export file \"$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/zycore/zycore-targets.cmake\" will be replaced.  Removing files [${_cmake_old_config_files_text}].")
        unset(_cmake_old_config_files_text)
        file(REMOVE ${_cmake_old_config_files})
      endif()
      unset(_cmake_old_config_files)
    endif()
    unset(_cmake_export_file_changed)
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/zycore" TYPE FILE FILES "C:/Users/Deniska/Downloads/Alcatraz-master/Alcatraz-master/vcpkg_installed/vcpkg/blds/zycore/x64-windows-dbg/CMakeFiles/Export/be8fb0d055ecad19586b2bae767d49d8/zycore-targets.cmake")
  if(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/zycore" TYPE FILE FILES "C:/Users/Deniska/Downloads/Alcatraz-master/Alcatraz-master/vcpkg_installed/vcpkg/blds/zycore/x64-windows-dbg/CMakeFiles/Export/be8fb0d055ecad19586b2bae767d49d8/zycore-targets-debug.cmake")
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include" TYPE DIRECTORY FILES "C:/Users/Deniska/Downloads/Alcatraz-master/Alcatraz-master/vcpkg_installed/vcpkg/blds/zycore/src/v1.5.0-7af075296a.clean/include/")
endif()

if(CMAKE_INSTALL_COMPONENT)
  set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
file(WRITE "C:/Users/Deniska/Downloads/Alcatraz-master/Alcatraz-master/vcpkg_installed/vcpkg/blds/zycore/x64-windows-dbg/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
