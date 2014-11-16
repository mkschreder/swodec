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
#include <unistd.h>
#include <glib.h>

#include <libswo/libswo.h>

#define BUFFER_SIZE	1024

static gchar *input_file = NULL;

static GOptionEntry entries[] = {
	{"input-file", 'i', 0, G_OPTION_ARG_STRING, &input_file,
		"Load trace data from file", NULL},
	{NULL, 0, 0, 0, NULL, NULL, NULL}
};

static void handle_hw_packet(const union libswo_packet *packet)
{
	printf("Hardware source (address = %u, size = %zu bytes, value = %x)\n",
		packet->hw.address, packet->hw.size - 1, packet->hw.value);
}

static void handle_inst_packet(const union libswo_packet *packet)
{
	printf("Instrumentation (address = %u, size = %zu bytes, value = %x)\n",
		packet->inst.address, packet->inst.size - 1,
		packet->inst.value);
}

static void handle_overflow_packet(const union libswo_packet *packet)
{
	(void)packet;
	printf("Overflow\n");
}

static void handle_ext_packet(const union libswo_packet *packet)
{
	const char *src;

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
	printf("Unknown data (size = %zu bytes)\n", packet->unknown.size);
}

static void handle_sync_packet(const union libswo_packet *packet)
{
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

	switch (packet->lts.relation) {
	case LIBSWO_LTS_REL_SYNC:
		tc = "";
		break;
	case LIBSWO_LTS_REL_TS:
		tc = ", timestamp packet delayed";
		break;
	case LIBSWO_LTS_REL_SRC:
		tc = ", source packet delayed";
		break;
	case LIBSWO_LTS_REL_BOTH:
		tc = ", source and timestamp packet delayed";
		break;
	}

	printf("Local timestamp (value = %x%s)\n", packet->lts.value, tc);
}

static void handle_gts1_packet(const union libswo_packet *packet)
{
	printf("Global timestamp (GTS1) (value = %x, wrap = %u, clkch = %u)\n",
		packet->gts1.value, packet->gts1.wrap, packet->gts1.clkch);
}

static void handle_gts2_packet(const union libswo_packet *packet)
{
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

	if (!parse_options(&argc, &argv))
		return EXIT_FAILURE;

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

	if (ret != LIBSWO_OK) {
		g_critical("libswo_feed() failed: %s.\n",
			libswo_strerror_name(ret));
		g_io_channel_unref(input);
		libswo_exit(ctx);
		return EXIT_FAILURE;
	}

	g_io_channel_unref(input);
	libswo_exit(ctx);

	return EXIT_SUCCESS;
}
