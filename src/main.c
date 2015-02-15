/*
 * This file is part of the swodec project.
 *
 * Copyright (C) 2014-2015 Marc Schink <swo-dev@marcschink.de>
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
#include <unistd.h>
#include <string.h>
#include <glib.h>

#include <libswo/libswo.h>

#define BUFFER_SIZE	1024

static gchar *input_file = NULL;
static uint16_t packet_type_filter;
static uint32_t inst_address_filter;
static gboolean opt_dump_inst;
static gboolean opt_decode_dwt;

void dwt_handle_packet(const struct libswo_packet_hw *packet);

static gboolean parse_filter_option(const gchar *option_name,
		const gchar *value, gpointer data, GError **error)
{
	gchar **tokens;
	unsigned int i;
	uint16_t tmp;
	gboolean invert;

	(void)option_name;
	(void)data;
	(void)error;

	if (!strlen(value))
		return TRUE;

	if (value[0] == '~') {
		value++;
		invert = TRUE;
	} else {
		invert = FALSE;
	}

	i = 0;
	tokens = g_strsplit(value, ",", -1);
	tmp = 0x0000;

	while (tokens[i]) {
		g_strstrip(tokens[i]);

		if (!strlen(tokens[i])) {
			i++;
			continue;
		}

		if (!g_ascii_strcasecmp(tokens[i], "sync")) {
			tmp |= (1 << LIBSWO_PACKET_TYPE_SYNC);
		} else if (!g_ascii_strcasecmp(tokens[i], "of")) {
			tmp |= (1 << LIBSWO_PACKET_TYPE_OVERFLOW);
		} else if (!g_ascii_strcasecmp(tokens[i], "lts")) {
			tmp |= (1 << LIBSWO_PACKET_TYPE_LTS);
		} else if (!g_ascii_strcasecmp(tokens[i], "gts")) {
			tmp |= (1 << LIBSWO_PACKET_TYPE_GTS1);
			tmp |= (1 << LIBSWO_PACKET_TYPE_GTS2);
		} else if (!g_ascii_strcasecmp(tokens[i], "gts1")) {
			tmp |= (1 << LIBSWO_PACKET_TYPE_GTS1);
		} else if (!g_ascii_strcasecmp(tokens[i], "gts2")) {
			tmp |= (1 << LIBSWO_PACKET_TYPE_GTS2);
		} else if (!g_ascii_strcasecmp(tokens[i], "ext")) {
			tmp |= (1 << LIBSWO_PACKET_TYPE_EXT);
		} else if (!g_ascii_strcasecmp(tokens[i], "inst")) {
			tmp |= (1 << LIBSWO_PACKET_TYPE_INST);
		} else if (!g_ascii_strcasecmp(tokens[i], "hw")) {
			tmp |= (1 << LIBSWO_PACKET_TYPE_HW);
		} else if (!g_ascii_strcasecmp(tokens[i], "unknown")) {
			tmp |= (1 << LIBSWO_PACKET_TYPE_UNKNOWN);
		} else {
			g_critical("Invalid packet type: %s.", tokens[i]);
			g_strfreev(tokens);
			return FALSE;
		}

		i++;
	}

	if (invert)
		tmp = ~tmp;

	/*
	 * Apply the packet type filter only if at least one valid packet type
	 * was specified.
	 */
	if (tmp > 0)
		packet_type_filter = tmp;

	g_strfreev(tokens);

	return TRUE;
}

static gboolean parse_inst_filter_option(const gchar *option_name,
		const gchar *value, gpointer data, GError **error)
{
	gchar **tokens;
	unsigned int i;
	uint32_t tmp;
	long int address;
	char *endptr;
	gboolean invert;

	(void)option_name;
	(void)data;
	(void)error;

	if (!strlen(value))
		return TRUE;

	if (value[0] == '~') {
		value++;
		invert = TRUE;
	} else {
		invert = FALSE;
	}

	i = 0;
	tokens = g_strsplit(value, ",", -1);
	tmp = 0x00000000;

	while (tokens[i]) {
		g_strstrip(tokens[i]);

		if (!strlen(tokens[i])) {
			i++;
			continue;
		}

		address = strtoll(tokens[i], &endptr, 10);

		if (endptr == tokens[i] || *endptr != '\0') {
			g_critical("Invalid source address: %s.", tokens[i]);
			g_strfreev(tokens);
			return FALSE;
		}

		if (address < 0 || address > 31) {
			g_critical("Source address out of range: %li.",
				address);
			g_strfreev(tokens);
			return FALSE;
		}

		tmp |= (1 << address);
		i++;
	}

	if (invert)
		tmp = ~tmp;

	/*
	 * Apply the instrumentation source address filter only if at least one
	 * valid source address was specified.
	 */
	if (tmp > 0)
		inst_address_filter = tmp;

	g_strfreev(tokens);

	return TRUE;
}

static GOptionEntry entries[] = {
	{"input-file", 'i', 0, G_OPTION_ARG_STRING, &input_file,
		"Load trace data from file", NULL},
	{"filter", 'f', 0, G_OPTION_ARG_CALLBACK, &parse_filter_option,
		"Filter for packet types", NULL},
	{"filter-inst", 0, 0, G_OPTION_ARG_CALLBACK, &parse_inst_filter_option,
		"Filter for instrumentation source addresses", NULL},
	{"dump-inst", 0, 0, G_OPTION_ARG_NONE, &opt_dump_inst,
		"Dump instrumentation payload", NULL},
	{"dwt", 0, 0, G_OPTION_ARG_NONE, &opt_decode_dwt,
		"Enable DWT decoder", NULL},
	{NULL, 0, 0, 0, NULL, NULL, NULL}
};

static void handle_hw_packet(const union libswo_packet *packet)
{
	if (!(packet_type_filter & (1 << LIBSWO_PACKET_TYPE_HW)))
		return;

	if (opt_decode_dwt) {
		dwt_handle_packet(&packet->hw);
		return;
	}

	printf("Hardware source (address = %u, value = %x, size = %zu bytes)\n",
		packet->hw.address, packet->hw.value, packet->hw.size - 1);
}

static void handle_inst_packet(const union libswo_packet *packet)
{
	if (!(packet_type_filter & (1 << LIBSWO_PACKET_TYPE_INST)))
		return;

	if (!(inst_address_filter & (1 << packet->inst.address)))
		return;

	if (opt_dump_inst) {
		fwrite(packet->inst.payload, packet->inst.size - 1, 1, stdout);
		fflush(stdout);
		return;
	}

	printf("Instrumentation (address = %u, value = %x, size = %zu bytes)\n",
		packet->inst.address, packet->inst.value,
		packet->inst.size - 1);
}

static void handle_overflow_packet(const union libswo_packet *packet)
{
	if (!(packet_type_filter & (1 << LIBSWO_PACKET_TYPE_OVERFLOW)))
		return;

	(void)packet;
	printf("Overflow\n");
}

static void handle_ext_packet(const union libswo_packet *packet)
{
	const char *src;

	if (!(packet_type_filter & (1 << LIBSWO_PACKET_TYPE_EXT)))
		return;

	switch (packet->ext.source) {
	case LIBSWO_EXT_SRC_ITM:
		src = "ITM";
		break;
	case LIBSWO_EXT_SRC_HW:
		src = "HW";
		break;
	}

	printf("Extension (source = %s, value = %x)\n", src,
		packet->ext.value);
}

static void handle_unknown_packet(const union libswo_packet *packet)
{
	if (!(packet_type_filter & (1 << LIBSWO_PACKET_TYPE_UNKNOWN)))
		return;

	printf("Unknown data (size = %zu bytes)\n", packet->unknown.size);
}

static void handle_sync_packet(const union libswo_packet *packet)
{
	if (!(packet_type_filter & (1 << LIBSWO_PACKET_TYPE_SYNC)))
		return;

	if (packet->sync.size % 8)
		printf("Synchronisation (size = %zu bits)\n",
			packet->sync.size);
	else
		printf("Synchronisation (size = %zu bytes)\n",
			packet->sync.size / 8);
}

static void handle_lts_packet(const union libswo_packet *packet)
{
	const char *tc;

	if (!(packet_type_filter & (1 << LIBSWO_PACKET_TYPE_LTS)))
		return;

	switch (packet->lts.relation) {
	case LIBSWO_LTS_REL_SYNC:
		tc = "synchronous";
		break;
	case LIBSWO_LTS_REL_TS:
		tc = "timestamp delayed";
		break;
	case LIBSWO_LTS_REL_SRC:
		tc = "data delayed";
		break;
	case LIBSWO_LTS_REL_BOTH:
		tc = "data and timestamp delayed";
		break;
	}

	printf("Local timestamp (relation = %s, value = %x)\n", tc,
		packet->lts.value);
}

static void handle_gts1_packet(const union libswo_packet *packet)
{
	if (!(packet_type_filter & (1 << LIBSWO_PACKET_TYPE_GTS1)))
		return;

	printf("Global timestamp (GTS1) (wrap = %u, clkch = %u, value = %x)\n",
		packet->gts1.wrap, packet->gts1.clkch, packet->gts1.value);
}

static void handle_gts2_packet(const union libswo_packet *packet)
{
	if (!(packet_type_filter & (1 << LIBSWO_PACKET_TYPE_GTS2)))
		return;

	printf("Global timestamp (GTS2) (value = %x)\n", packet->gts2.value);
}

static int packet_cb(struct libswo_context *ctx,
		const union libswo_packet *packet, void *user_data)
{
	(void)ctx;
	(void)user_data;

	switch (packet->type) {
	case LIBSWO_PACKET_TYPE_SYNC:
		handle_sync_packet(packet);
		break;
	case LIBSWO_PACKET_TYPE_INST:
		handle_inst_packet(packet);
		break;
	case LIBSWO_PACKET_TYPE_OVERFLOW:
		handle_overflow_packet(packet);
		break;
	case LIBSWO_PACKET_TYPE_EXT:
		handle_ext_packet(packet);
		break;
	case LIBSWO_PACKET_TYPE_LTS:
		handle_lts_packet(packet);
		break;
	case LIBSWO_PACKET_TYPE_GTS1:
		handle_gts1_packet(packet);
		break;
	case LIBSWO_PACKET_TYPE_GTS2:
		handle_gts2_packet(packet);
		break;
	case LIBSWO_PACKET_TYPE_HW:
		handle_hw_packet(packet);
		break;
	case LIBSWO_PACKET_TYPE_UNKNOWN:
		handle_unknown_packet(packet);
		break;
	default:
		break;
	}

	return 0;
}

static int parse_options(int *argc, char ***argv)
{
	GError *error;
	GOptionContext *context;

	error = NULL;

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, entries, NULL);

	if (!g_option_context_parse(context, argc, argv, &error)) {
		g_critical("%s.\n", error->message);
		g_error_free(error);
		g_option_context_free(context);
		return FALSE;
	}

	g_option_context_free(context);

	return TRUE;
}

int main(int argc, char **argv)
{
	int ret;
	struct libswo_context *ctx;
	uint8_t buffer[BUFFER_SIZE];
	GIOChannel *input;
	GError *error;
	GIOStatus iostat;
	gsize num;

	opt_dump_inst = FALSE;
	opt_decode_dwt = FALSE;

	/* Disable packet filtering for all packet types by default. */
	packet_type_filter = (1 << LIBSWO_PACKET_TYPE_SYNC) | \
		(1 << LIBSWO_PACKET_TYPE_OVERFLOW) | \
		(1 << LIBSWO_PACKET_TYPE_LTS) | \
		(1 << LIBSWO_PACKET_TYPE_GTS1) | \
		(1 << LIBSWO_PACKET_TYPE_GTS2) | \
		(1 << LIBSWO_PACKET_TYPE_EXT) | \
		(1 << LIBSWO_PACKET_TYPE_INST) | \
		(1 << LIBSWO_PACKET_TYPE_HW) | \
		(1 << LIBSWO_PACKET_TYPE_UNKNOWN);

	/* Disable instrumentation source address filtering by default. */
	inst_address_filter = 0xffffffff;

	if (!parse_options(&argc, &argv))
		return EXIT_FAILURE;

	if (opt_dump_inst)
		packet_type_filter = (1 << LIBSWO_PACKET_TYPE_INST);

	error = NULL;

	if (input_file) {
		input = g_io_channel_new_file(input_file, "r", &error);

		if (!input) {
			g_critical("%s: %s.\n", input_file, error->message);
			g_error_free(error);
			g_free(input_file);
			return EXIT_FAILURE;
		}

		g_free(input_file);
	} else {
		input = g_io_channel_unix_new(STDIN_FILENO);
	}

	/* Set encoding to binary (default is UTF-8). */
	iostat = g_io_channel_set_encoding(input, NULL, &error);

	if (iostat != G_IO_STATUS_NORMAL) {
		g_critical("%s.\n", error->message);
		g_error_free(error);
		g_io_channel_unref(input);
		return EXIT_FAILURE;
	}

	if (!input_file)
		g_io_channel_set_buffered(input, FALSE);

	ret = libswo_init(&ctx, NULL, BUFFER_SIZE * 2);

	if (ret != LIBSWO_OK) {
		g_critical("libswo_init() failed: %s.\n",
			libswo_strerror_name(ret));
		g_io_channel_unref(input);
		return EXIT_FAILURE;
	}

	ret = libswo_set_callback(ctx, &packet_cb, NULL);

	if (ret != LIBSWO_OK) {
		g_critical("libswo_set_callback() failed: %s.\n",
			libswo_strerror_name(ret));
		g_io_channel_unref(input);
		libswo_exit(ctx);
		return EXIT_FAILURE;
	}

	while (TRUE) {
		iostat = g_io_channel_read_chars(input, (gchar *)buffer,
			BUFFER_SIZE, &num, &error);

		if (iostat == G_IO_STATUS_ERROR)
			break;

		ret = libswo_feed(ctx, buffer, num);

		if (ret != LIBSWO_OK) {
			g_critical("libswo_feed() failed: %s.\n",
				libswo_strerror_name(ret));
			g_io_channel_unref(input);
			libswo_exit(ctx);
			return EXIT_FAILURE;
		}

		ret = libswo_decode(ctx, 0, 0);

		if (ret < LIBSWO_OK) {
			g_critical("libswo_decode() failed: %s.\n",
				libswo_strerror_name(ret));
			g_io_channel_unref(input);
			libswo_exit(ctx);
			return EXIT_FAILURE;
		}

		if (iostat == G_IO_STATUS_EOF)
			break;
	}

	if (iostat == G_IO_STATUS_ERROR) {
		g_critical("%s.\n", error->message);
		g_error_free(error);
		g_io_channel_unref(input);
		libswo_exit(ctx);
		return EXIT_FAILURE;
	}

	ret = libswo_decode(ctx, 0, LIBSWO_DF_EOS);

	if (ret < LIBSWO_OK) {
		g_critical("libswo_decode() failed: %s.\n",
			libswo_strerror_name(ret));
		g_io_channel_unref(input);
		libswo_exit(ctx);
		return EXIT_FAILURE;
	}

	g_io_channel_unref(input);
	libswo_exit(ctx);

	return EXIT_SUCCESS;
}
