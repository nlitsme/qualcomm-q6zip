cmake_minimum_required(VERSION 3.18)
project(cladetool)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake_find")

if (OPT_SYMBOLS)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g ")
endif()
if (OPT_ASAN)
    # https://gcc.gnu.org/onlinedocs/gcc-12.2.0/gcc/Instrumentation-Options.html#index-fsanitize_003daddress
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=undefined")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
    #set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=thread")
    #set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=dataflow")
elseif(OPT_TSAN)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=thread")
endif()

if (NOT HEXAGONTOOLS)
    set(HEXAGONTOOLS "/home/itsme/prj/hexagon/sdk/tools/HEXAGON_Tools/8.7.06/Tools/")
endif()
find_library(CLADE_PATH NAMES clade PATHS ${HEXAGONTOOLS}/lib/)
find_library(CLADE2_PATH NAMES clade2 PATHS ${HEXAGONTOOLS}/lib/)
find_path(CLADESDK_PATH NAMES clade_version.h PATHS ${HEXAGONTOOLS}/include/)

add_library(clade INTERFACE)
target_link_libraries(clade INTERFACE ${CLADE_PATH} ${CLADE2_PATH})
target_include_directories(clade INTERFACE ${CLADESDK_PATH})

find_package(cpputils)

add_executable(cladetool cladetool.cpp)
target_link_libraries(cladetool clade cpputils)
