cmake_minimum_required(VERSION 3.21)

Qt6_DIR=C:\Qt\6.10.2\msvc2022_64\lib\cmake\Qt6


project(FBBForensics LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

set(_showcase_qt_root "C:/Qt/6.10.2/msvc2022_64")
if(EXISTS "${_showcase_qt_root}/lib/cmake/Qt6/Qt6Config.cmake")
    list(PREPEND CMAKE_PREFIX_PATH "${_showcase_qt_root}")
    message(STATUS "Using configured Qt from ${_showcase_qt_root}")
elseif(NOT Qt6_DIR)
    file(GLOB _qt_versions LIST_DIRECTORIES true "C:/Qt/6.*")
    list(SORT _qt_versions COMPARE NATURAL ORDER DESCENDING)

    foreach(_qt_version IN LISTS _qt_versions)
        if(EXISTS "${_qt_version}/msvc2022_64/lib/cmake/Qt6/Qt6Config.cmake")
            list(PREPEND CMAKE_PREFIX_PATH "${_qt_version}/msvc2022_64")
            message(STATUS "Using auto-detected Qt from ${_qt_version}/msvc2022_64")
            break()
        endif()
    endforeach()
endif()

find_package(Qt6 REQUIRED COMPONENTS Core Sql)

option(SHOWCASE_ENABLE_TSK "Enable The Sleuth Kit support" ON)
option(SHOWCASE_ENABLE_EWF "Enable libewf support" ON)

add_executable(FBBForensics
    src/main.cpp
    src/showcaseapp.cpp
    src/showcaseanalyzer.cpp
    src/rawdevice.cpp
)

target_include_directories(FBBForensics PRIVATE src)
target_link_libraries(FBBForensics PRIVATE Qt6::Core Qt6::Sql)

if(SHOWCASE_ENABLE_TSK)
    find_path(TSK_INCLUDE_DIR tsk/libtsk.h)
    find_library(TSK_LIBRARY NAMES tsk libtsk)
    if(TSK_INCLUDE_DIR AND TSK_LIBRARY)
        target_compile_definitions(FBBForensics PRIVATE SHOWCASE_HAS_TSK=1)
        target_include_directories(FBBForensics PRIVATE ${TSK_INCLUDE_DIR})
        target_link_libraries(FBBForensics PRIVATE ${TSK_LIBRARY})
    else()
        message(WARNING "The Sleuth Kit was not found. Partition enumeration will be disabled.")
    endif()
endif()

if(SHOWCASE_ENABLE_EWF)
    find_path(LIBEWF_INCLUDE_DIR libewf.h)
    find_library(LIBEWF_LIBRARY NAMES ewf libewf)
    if(LIBEWF_INCLUDE_DIR AND LIBEWF_LIBRARY)
        target_compile_definitions(FBBForensics PRIVATE SHOWCASE_HAS_EWF=1)
        target_include_directories(FBBForensics PRIVATE ${LIBEWF_INCLUDE_DIR})
        target_link_libraries(FBBForensics PRIVATE ${LIBEWF_LIBRARY})
    else()
        message(WARNING "libewf was not found. E01 support will be disabled.")
    endif()
endif()
