AM_CPPFLAGS =                       \
    -g      \
    -I../../gtest/include/

AM_LDFLAGS = \
    -g \
    -pthread                \
    -lrt                    \
    -ldl                    \
    -lutil                  \
    -rdynamic               \
    -lexpat                 \
    -lcrypto

bin_PROGRAMS = websocket

websocket_SOURCES =\
    tcp.c \
    websocket.c \
    main.c
