cmake_minimum_required(VERSION 3.10)
project(TinyExpr C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -O2")

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
add_executable(repl-readline repl.c ${COMMON_OBJS})
target_compile_definitions(repl-readline PRIVATE USE_READLINE)
target_link_libraries(repl-readline ${LINK_LIBS} readline)

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
