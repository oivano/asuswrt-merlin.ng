/*
 * OpenConnect VPN Client Control for Asuswrt-Merlin
 * Copyright (C) 2024
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __RC_OPENCONNECT_H__
#define __RC_OPENCONNECT_H__

#define OPENCONNECT_CLIENT_MAX 2

/* OpenConnect client states */
typedef enum {
	OPENCONNECT_STATE_STOPPED = 0,
	OPENCONNECT_STATE_CONNECTING = 1,
	OPENCONNECT_STATE_CONNECTED = 2,
	OPENCONNECT_STATE_ERROR = -1
} openconnect_state_t;

/* OpenConnect error codes */
typedef enum {
	OPENCONNECT_ERRNO_NONE = 0,
	OPENCONNECT_ERRNO_AUTH_FAILED = 1,
	OPENCONNECT_ERRNO_SERVER_UNREACHABLE = 2,
	OPENCONNECT_ERRNO_CERT_ERROR = 3,
	OPENCONNECT_ERRNO_CONFIG_ERROR = 4,
	OPENCONNECT_ERRNO_CONNECTION_LOST = 5,
	OPENCONNECT_ERRNO_UNKNOWN = 99
} openconnect_errno_t;

/* OpenConnect protocol types */
typedef enum {
	OPENCONNECT_PROTO_ANYCONNECT = 0,
	OPENCONNECT_PROTO_NC = 1,        /* Juniper Network Connect */
	OPENCONNECT_PROTO_PULSE = 2,     /* Pulse Secure */
	OPENCONNECT_PROTO_GP = 3,        /* GlobalProtect */
	OPENCONNECT_PROTO_F5 = 4,        /* F5 Big-IP */
	OPENCONNECT_PROTO_FORTINET = 5   /* Fortinet */
} openconnect_protocol_t;

/* Function prototypes */
int start_openconnect_client(int unit);
void stop_openconnect_client(int unit);
void stop_openconnect_all(void);
int openconnect_client_enabled(int unit);
void update_openconnect_status(int unit, openconnect_state_t state, openconnect_errno_t err);
int get_openconnect_status(int unit);
int get_openconnect_errno(int unit);
int write_openconnect_config(int unit);
void openconnect_up_handler(int unit);
void openconnect_down_handler(int unit);
int is_openconnect_running(int unit);

#endif /* __RC_OPENCONNECT_H__ */
