set(SOURCES ${PROJECT_SOURCE_DIR}/src/bpf_kprobe.c)
add_executable(bpf-kprobe ${SOURCES})
target_link_libraries(bpf-kprobe -lbcc)
