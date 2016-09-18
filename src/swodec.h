/*
 * This file is part of the swodec project.
 *
 * Copyright (C) 2015 Marc Schink <swo-dev@marcschink.de>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef SWODEC_SWODEC_H
#define SWODEC_SWODEC_H

#include <libswo/libswo.h>

/* Data Watchpoint and Trace (DWT) packet types. */
enum dwt_packet_type {
	/* Event counter packet. */
	DWT_PACKET_TYPE_EVENT_COUNTER = LIBSWO_PACKET_TYPE_HW + 1,
	/* Exception trace packet. */
	DWT_PACKET_TYPE_EXCEPTION_TRACE,
	/* Periodic PC sample packet. */
	DWT_PACKET_TYPE_PC_SAMPLE,
	/* Data trace PC value packet. */
	DWT_PACKET_TYPE_DT_PC_VALUE,
	/* Data trace address offset packet. */
	DWT_PACKET_TYPE_DT_ADDR_OFFSET,
	/* Data trace data value packet. */
	DWT_PACKET_TYPE_DT_DATA_VALUE
};

extern uint16_t packet_type_filter;

gboolean dwt_handle_packet(const struct libswo_packet_hw *packet);

#endif /* SWODEC_SWODEC_H */
