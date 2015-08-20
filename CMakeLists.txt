cmake_minimum_required(VERSION 2.8.8)

project(pimbd C)

set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -std=c99")

add_definitions(-D_GNU_SOURCE -Wall -Wno-gnu)

if(${L_LEVEL})
  add_definitions(-DL_LEVEL=${L_LEVEL})
endif(${L_LEVEL})

if(WITH_LIBUBOX)
  add_definitions(-Wextra)
  set(PLATFORM_LINK ${PLATFORM_LINK} ubox blobmsg_json)
else (WITH_LIBUBOX)
  add_definitions(-Dtypeof=__typeof)
  include_directories(BEFORE .)
  set(PLATFORM_SOURCE ${PLATFORM_SOURCE} libubox/uloop.c libubox/avl.c libubox/blobmsg.c libubox/blob.c
	  libubox/blobmsg_json.c libubox/usock.c libubox/ustream.c libubox/ustream-fd.c)
  set(PLATFORM_LINK json-c)
endif(WITH_LIBUBOX)

install(CODE "execute_process(COMMAND mkdir -p \$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/sbin/)")
install(CODE "execute_process(COMMAND cp generic/pimbc.sh \$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/sbin/pimbc)")
install(CODE "execute_process(COMMAND ln -sf pimbd \$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/sbin/pimb-ipc)")

install(FILES generic/pimbc.man DESTINATION /usr/share/man/man8 RENAME pimbc.8)
install(FILES generic/pimbd.man DESTINATION /usr/share/man/man8 RENAME pimbd.8)

# pimbd
add_executable(pimbd src/pimbd.c src/ifgroup.c src/pim.c src/pim_proto.c src/pim_neigh.c
src/pim_rpa.c src/pim_group.c src/rib.c src/rtnl.c src/conf.c src/utils.c src/ipc.c
src/mrib.c src/querier.c src/groups.c src/igmp.c src/mld.c src/listener.c
src/pim_jp.c src/monitor.c src/pim_ctl.c src/pim_proxy.c
${PLATFORM_SOURCE})
target_link_libraries(pimbd ${PLATFORM_LINK})
install(TARGETS pimbd DESTINATION sbin/)

#Building OpenWrt package Makefile
add_custom_command(OUTPUT openwrt/package/Makefile
                   COMMAND cat openwrt/Makefile.input | sed \"s\\\\GIT_COMMIT_ID\\\\`git log --pretty=format:'%H' -n 1`\\\\\" > openwrt/package/Makefile
                   DEPENDS openwrt/Makefile.input
                   )
add_custom_target(openwrt_package
                  DEPENDS openwrt/package/Makefile
                  )

