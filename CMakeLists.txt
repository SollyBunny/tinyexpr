cmake_minimum_required(VERSION 3.10)
project(TinyExpr C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if (CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -Wall -Wextra -Wpedantic -Werror -Wshadow -Wconversion -Wundef -Wcast-align -Wstrict-prototypes")
elseif (CMAKE_C_COMPILER_ID STREQUAL "MSVC")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /O2 /W4 /WX /permissive-")
endif()

set(LINK_LIBS m)

# Shared source
set(TINYEXPR_SRC tinyexpr.c)
set(COMMON_OBJS ${TINYEXPR_SRC})

# Smoke
add_executable(smoke smoke.c ${COMMON_OBJS})
target_link_libraries(smoke ${LINK_LIBS})
add_custom_command(TARGET smoke POST_BUILD COMMAND smoke)

# Smoke with custom defines
add_executable(smoke_pr smoke.c ${COMMON_OBJS})
target_compile_definitions(smoke_pr PRIVATE TE_POW_FROM_RIGHT TE_NAT_LOG)
target_link_libraries(smoke_pr ${LINK_LIBS})
add_custom_command(TARGET smoke_pr POST_BUILD COMMAND smoke_pr)

# repl
add_executable(repl repl.c ${COMMON_OBJS})
target_link_libraries(repl ${LINK_LIBS})

# repl-readline
option(USE_READLINE "Enable readline support" "")

if(NOT DEFINED USE_READLINE)
    find_path(READLINE_INCLUDE_DIR readline/readline.h)
    find_library(READLINE_LIBRARY readline)
    if(READLINE_INCLUDE_DIR AND READLINE_LIBRARY)
        set(USE_READLINE 1)
    else()
        set(USE_READLINE 0)
    endif()
endif()

add_executable(repl-readline repl.c ${COMMON_OBJS})
if(USE_READLINE)
    target_compile_definitions(repl-readline PRIVATE USE_READLINE)
    target_include_directories(repl-readline PRIVATE ${READLINE_INCLUDE_DIR})
    target_link_libraries(repl-readline PRIVATE ${LINK_LIBS} ${READLINE_LIBRARY})
else()
    target_link_libraries(repl-readline PRIVATE ${LINK_LIBS})
endif()

# benchmark
add_executable(bench benchmark.c ${COMMON_OBJS})
target_link_libraries(bench ${LINK_LIBS})

# examples
add_executable(example example.c ${COMMON_OBJS})
target_link_libraries(example ${LINK_LIBS})

add_executable(example2 example2.c ${COMMON_OBJS})
target_link_libraries(example2 ${LINK_LIBS})

add_executable(example3 example3.c ${COMMON_OBJS})
target_link_libraries(example3 ${LINK_LIBS})
