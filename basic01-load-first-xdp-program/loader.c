/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>

#include <getopt.h>


int main(int argc, char **argv) {
    struct option long_options[] = {{"dev",         1, 0, 'd'},
                                    {"skb-mode",    0, 0, 'S'},
                                    {"native-mode", 1, 0, 'N'},
                                    {"help",        0, 0, 'h'}
    };

    int c;
    while ((c = getopt_long(argc, argv, "d:SNh", long_options, &option_index)) != EOF) {
        switch (c) {
            case 'd':
                printf("-d is %s\n", optarg);
            case 'S':
                printf("SKB mode\n");
            case 'N':
                printf("Native mode\n");
            case 'h':
                printf("call usage()\n");
                break;
            default:
                printf("This is default\n");
        }
    }
}