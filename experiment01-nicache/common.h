/*
 *  SPDX-FileCopyrightText: Copyright (c) 2021 Orange
 *  SPDX-License-Identifier: LGPL-2.1-only
 *
 *  This software is distributed under the
 *  GNU Lesser General Public License v2.1 only.
 *
 */

#ifndef _COMMON_H
#define _COMMON_H

#define MAX_KEY_LENGTH 16
#define MAX_VAL_LENGTH 32
#define MAX_CACHE_ENTRY_COUNT 1000000
#define MAX_PACKET_LENGTH 1500

struct key_entry {
    char data[MAX_KEY_LENGTH];
};

struct cache_entry {
    unsigned short len;
    char data[MAX_VAL_LENGTH];
};

#endif
