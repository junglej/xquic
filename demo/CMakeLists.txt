### hq demo client/server ###
set(
    HQ_SOURCES
    "xqc_hq_ctx.c"
    "xqc_hq_conn.c"
    "xqc_hq_request.c"
)

set(
    DEMO_CLIENT_SOURCES
    ${HQ_SOURCES}
    "demo_client.c"
    "${CMAKE_SOURCE_DIR}/../Lib/wpa_ctrl/wpa_ctrl.c"
)

set(
    DEMO_SERVER_SOURCES
    ${HQ_SOURCES}
    "demo_server.c"
)


if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set(DEMO_SERVER_SOURCES
        ${DEMO_SERVER_SOURCES}
        ${GETOPT_SOURCES}
    )

    set(DEMO_CLIENT_SOURCES
        ${DEMO_CLIENT_SOURCES}
        ${GETOPT_SOURCES}
    )
endif()

include_directories(
    "${CMAKE_SOURCE_DIR}/"
    "${CMAKE_SOURCE_DIR}/include"
    ${CMAKE_SOURCE_DIR}
    ${CUNIT_INCLUDE_DIRS}
    ${LIBEVENT_INCLUDE_DIR}
    "${CMAKE_SOURCE_DIR}/../ebpf-wifi-insider"
    "${CMAKE_SOURCE_DIR}/../ebpf-wifi-insider/.output"
    "${CMAKE_SOURCE_DIR}/../Lib/libbpf/include/uapi"
    "${CMAKE_SOURCE_DIR}/../Lib/libbpf/src"
    "${CMAKE_SOURCE_DIR}/../Lib/wpa_ctrl"
)

set(DEMO_WIFI_MONITOR_DIR "${CMAKE_SOURCE_DIR}/../ebpf-wifi-insider")
set(DEMO_WIFI_MONITOR_OUTPUT "${DEMO_WIFI_MONITOR_DIR}/.output")
set(DEMO_WIFI_MONITOR_SKEL "${DEMO_WIFI_MONITOR_OUTPUT}/monitor.skel.h")
set(DEMO_WIFI_MONITOR_LIBBPF "${DEMO_WIFI_MONITOR_OUTPUT}/libbpf.a")

if(XQC_ENABLE_WIFI_MONITOR AND NOT CMAKE_SYSTEM_NAME MATCHES "Windows")
    set(DEMO_WIFI_MONITOR_LIBBPF "${XQC_WIFI_MONITOR_LIBBPF}")
else()
    add_custom_command(
        OUTPUT "${DEMO_WIFI_MONITOR_SKEL}" "${DEMO_WIFI_MONITOR_LIBBPF}"
        COMMAND ${CMAKE_MAKE_PROGRAM} -C "${DEMO_WIFI_MONITOR_DIR}" .output/monitor.skel.h .output/libbpf.a
        DEPENDS
            "${DEMO_WIFI_MONITOR_DIR}/monitor.c"
            "${DEMO_WIFI_MONITOR_DIR}/monitor.bpf.c"
            "${DEMO_WIFI_MONITOR_DIR}/monitor.h"
        VERBATIM
    )

    add_custom_target(demo_wifi_monitor_assets
        DEPENDS "${DEMO_WIFI_MONITOR_SKEL}" "${DEMO_WIFI_MONITOR_LIBBPF}")
endif()

add_executable(demo_server ${DEMO_SERVER_SOURCES})
add_executable(demo_client ${DEMO_CLIENT_SOURCES})
if(NOT XQC_ENABLE_WIFI_MONITOR OR CMAKE_SYSTEM_NAME MATCHES "Windows")
    add_dependencies(demo_client demo_wifi_monitor_assets)
endif()

target_link_libraries(demo_server ${APP_DEPEND_LIBS})
target_link_libraries(
    demo_client
    ${APP_DEPEND_LIBS}
    "${DEMO_WIFI_MONITOR_LIBBPF}"
    elf
    z
)
