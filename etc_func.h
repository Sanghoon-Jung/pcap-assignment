#pragma once
#include <stdio.h>

void usage(char* path) {
    printf("syntax: %s <network interface>\n", path);
    printf("sample: %s wlan0\n", path);
}