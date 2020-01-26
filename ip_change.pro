TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
LIBS += -lnetfilter_queue

SOURCES += \
        cpp/check_checksum.cpp \
        cpp/ip_change.cpp \
        cpp/main.cpp \
        cpp/set_iptables.cpp \
        cpp/show.cpp

HEADERS += \
    header/header.h
