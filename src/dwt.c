/*
 * This file is part of the swodec project.
 *
 * Copyright (C) 2014 Marc Schink <swo-dev@marcschink.de>
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

#include <stdio.h>
#include <stdint.h>

#include <libswo/libswo.h>

/* Event counter packet discriminator ID. */
#define EVCNT_ID		0

/* Size of an event counter packet in bytes. */
#define EVCNT_SIZE		2

/* Bitmask for the CPI flag of an event counter packet. */
#define EVCNT_CPI_MASK		0x01

/* Bitmask for the Exc flag of an event counter packet. */
#define EVCNT_EXC_MASK		0x02

/* Bitmask for the Sleep flag of an event counter packet. */
#define EVCNT_SLEEP_MASK	0x04

/* Bitmask for the LSU flag of an event counter packet. */
#define EVCNT_LSU_MASK		0x08

/* Bitmask for the Fold flag of an event counter packet. */
#define EVCNT_FOLD_MASK		0x10

/* Bitmask for the Cyc flag of an event counter packet. */
#define EVCNT_CYC_MASK		0x20

/* Exception trace packet discriminator ID. */
#define EXTRACE_ID		1

/* Size of an exception trace packet in bytes. */
#define EXTRACE_SIZE		3

/* Bitmask for the exception number of an exception trace packet. */
#define EXTRACE_EX_MASK		0x01

/* Offset of the exception number of an exception trace packet. */
#define EXTRACE_EX_OFFSET	8

/* Bitmask for the function of an exception trace packet. */
#define EXTRACE_FN_MASK		0x30

/* Offset of the function of an exception trace packet. */
#define EXTRACE_FN_OFFSET	4

/* Periodic PC sample packet discriminator ID. */
#define PC_SAMPLE_ID		2

/* Size of a periodic PC sleep packet in bytes. */
#define PC_SAMPLE_SLEEP_SIZE	2

/* Size of a periodic PC sample packet in bytes. */
#define PC_SAMPLE_SIZE		5

/* Bitmask for the comparator number of a data trace packet. */
#define CMPN_MASK		0x06

/* Offset of the comparator number of a data trace packet. */
#define CMPN_OFFSET		1

/* Bitmask for the WnR flag of a data trace data value packet. */
#define WNR_MASK		0x01

/* Bitmask for the data trace PC value packet header. */
#define PC_VALUE_HEADER_MASK	0x19

/* Data trace PC value packet header. */
#define PC_VALUE_HEADER		0x08

/* Size of a data trace PC value packet in bytes. */
#define PC_VALUE_SIZE		5

/* Bitmask for the data trace address offset packet header. */
#define ADDR_OFFSET_HEADER_MASK	0x19

/* Data trace address offset packet header. */
#define ADDR_OFFSET_HEADER	0x09

/* Size of a data trace address offset packet in bytes. */
#define ADDR_OFFSET_SIZE	3

/* Bitmask for the data trace data value packet header. */
#define DATA_VALUE_HEADER_MASK	0x18

/* Data trace data value packet header. */
#define DATA_VALUE_HEADER	0x10

/* Exception trace functions. */
enum extrace_function {
	/* Enter exception. */
	EXTRACE_FN_ENTER = 1,
	/* Exit exception. */
	EXTRACE_FN_EXIT = 2,
	/* Return to exception. */
	EXTRACE_FN_RETURN = 3
};

static void handle_evcnt_packet(const struct libswo_packet_hw *packet)
{
	unsigned int cpi;
	unsigned int exc;
	unsigned int sleep;
	unsigned int lsu;
	unsigned int fold;
	unsigned int cyc;

	if (packet->size != EVCNT_SIZE) {
		printf("Event counter packet with invalid size of %zu bytes.\n",
			packet->size);
		return;
	}

	if (packet->payload[0] & EVCNT_CPI_MASK)
		cpi = 1;
	else
		cpi = 0;

	if (packet->payload[0] & EVCNT_EXC_MASK)
		exc = 1;
	else
		exc = 0;

	if (packet->payload[0] & EVCNT_SLEEP_MASK)
		sleep = 1;
	else
		sleep = 0;

	if (packet->payload[0] & EVCNT_LSU_MASK)
		lsu = 1;
	else
		lsu = 0;

	if (packet->payload[0] & EVCNT_FOLD_MASK)
		fold = 1;
	else
		fold = 0;

	if (packet->payload[0] & EVCNT_CYC_MASK)
		cyc = 1;
	else
		cyc = 0;

	printf("Event counter (CPI = %u, exc = %u, sleep = %u, LSU = %u, "
		"fold = %u, cyc = %u)\n", cpi, exc, sleep, lsu, fold, cyc);
}

static void handle_extrace_packet(const struct libswo_packet_hw *packet)
{
	uint16_t exception;
	uint8_t tmp;
	const char *func;

	if (packet->size != EXTRACE_SIZE) {
		printf("Exception trace packet with invalid size of "
			"%zu bytes.\n", packet->size);
		return;
	}

	exception = packet->payload[0];
	exception |= (packet->payload[1] & EXTRACE_EX_MASK) << \
		EXTRACE_EX_OFFSET;
	tmp = (packet->payload[1] & EXTRACE_FN_MASK) >> EXTRACE_FN_OFFSET;

	switch (tmp) {
	case EXTRACE_FN_ENTER:
		func = "enter";
		break;
	case EXTRACE_FN_EXIT:
		func = "exit";
		break;
	case EXTRACE_FN_RETURN:
		func = "return";
		break;
	default:
		func = "reserved";
	}

	printf("Exception trace (function = %s, exception = %u)\n", func,
		exception);
}

static void handle_pc_sample_packet(const struct libswo_packet_hw *packet)
{
	if (packet->size == PC_SAMPLE_SLEEP_SIZE) {
		if (packet->value > 0) {
			printf("Periodic PC sleep packet contains invalid "
				"value: %x.\n", packet->value);
			return;
		}

		printf("Periodic PC sleep\n");
	} else if (packet->size == PC_SAMPLE_SIZE) {
		printf("Periodic PC sample (value = %x)\n", packet->value);
	} else {
		printf("Periodic PC sample packet with invalid size of "
			"%zu bytes.\n", packet->size);
		return;
	}
}

static void handle_pc_value_packet(const struct libswo_packet_hw *packet)
{
	unsigned int cmpn;

	if (packet->size != PC_VALUE_SIZE) {
		printf("Data trace PC value packet with invalid size of "
			"%zu bytes.\n", packet->size);
		return;
	}

	cmpn = (packet->address & CMPN_MASK) >> CMPN_OFFSET;

	printf("Data trace PC value (comparator = %u, value = %x)\n", cmpn,
		packet->value);
}

static void handle_address_offset_packet(const struct libswo_packet_hw *packet)
{
	unsigned int cmpn;

	if (packet->size != ADDR_OFFSET_SIZE) {
		printf("Data trace address offset packet with invalid size of "
			"%zu bytes.\n", packet->size);
		return;
	}

	cmpn = (packet->address & CMPN_MASK) >> CMPN_OFFSET;

	printf("Data trace address offset (comparator = %u, value = %x)\n",
		cmpn, packet->value);
}

static void handle_data_value_packet(const struct libswo_packet_hw *packet)
{
	unsigned int wnr;
	unsigned int cmpn;

	wnr = packet->address & WNR_MASK;
	cmpn = (packet->address & CMPN_MASK) >> CMPN_OFFSET;

	printf("Data trace data value (comparator = %u, WnR = %u, value = %x, "
		"size = %zu bytes)\n", cmpn, wnr, packet->value,
		packet->size - 1);
}

static void handle_unknown_packet(const struct libswo_packet_hw *packet)
{
	printf("Unknown DWT packet (ID = %u, value = %x, size = %zu bytes)\n",
		packet->address, packet->value, packet->size - 1);
}

void dwt_handle_packet(const struct libswo_packet_hw *packet)
{
	uint8_t addr;

	addr = packet->address;

	switch (addr) {
	case EVCNT_ID:
		handle_evcnt_packet(packet);
		return;
	case EXTRACE_ID:
		handle_extrace_packet(packet);
		return;
	case PC_SAMPLE_ID:
		handle_pc_sample_packet(packet);
		return;
	default:
		break;
	}

	if ((addr & PC_VALUE_HEADER_MASK) == PC_VALUE_HEADER) {
		handle_pc_value_packet(packet);
	} else if ((addr & ADDR_OFFSET_HEADER_MASK) == ADDR_OFFSET_HEADER) {
		handle_address_offset_packet(packet);
	} else if ((addr & DATA_VALUE_HEADER_MASK) == DATA_VALUE_HEADER) {
		handle_data_value_packet(packet);
	} else {
		handle_unknown_packet(packet);
	}
}
