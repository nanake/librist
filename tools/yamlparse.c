/* librist. Copyright © 2024 SipRadius LLC. All right reserved.
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <yamlparse.h>
#include <ctype.h>
#include <string.h>
#include "headers.h"
#include "logging.h"

#ifndef strndup
char *strndup (const char *str, size_t max)
{
    size_t len = strnlen (str, max);
    char *res = malloc (len + 1);
    if (res)
    {
        memcpy (res, str, len);
        res[len] = '\0';
    }
    return res;
}
#endif

size_t rist_findchar(const char* str, int c, size_t max) {
    size_t position = 0;
    size_t i = 0;
    for(i = 0; ;i++) {
        if((unsigned char) str[i] == c) {
            position = i;
            break;
        }
        if (str[i]=='\0') break;
		if (i >= (max-1)) break;
    }
    return position;
}

yaml_node *parse_yaml_value(char *str, size_t *index, size_t *max) {
    yaml_node *node = malloc(sizeof(yaml_node));
	size_t start_pos = 0;
    node->key = NULL;
    node->value = NULL;
    node->next = NULL;

	// First remove all leading spaces
	while (isspace(str[*index + start_pos])) (start_pos)++;

	// Find next \n
	size_t cr_pos = rist_findchar(&str[*index + start_pos], '\n', *max - *index);

	if (cr_pos == 0)
	{
		*index = *max;
		return NULL;
	}

	// Find the first space in this line (if any)
	size_t space_pos = rist_findchar(&str[*index + start_pos], ' ', cr_pos);

	if (space_pos == 0 && str[*index + start_pos + cr_pos - 1] == ':') // Key only
	{
		node->key = strndup(str + *index + start_pos, cr_pos - 1);
		//printf("Key =%s=\n", node->key);
	}
	else if (space_pos < cr_pos && str[*index + start_pos + space_pos - 1] == ':') // Key Value pairs
	{
		node->key = strndup(str + *index + start_pos, space_pos - 1);
		// Remove any additional spaces before the value
		while (isspace(str[*index + start_pos + space_pos])) (space_pos)++;
		node->value = strndup(str + *index + start_pos + space_pos, cr_pos - space_pos);
		//printf("Key =%s= Value =%s=\n", node->key, node->value);
	}
	else // Value only
	{
		// If this is a list, remove the dash and space from it
		size_t skip_chars = 0;
		if (str[*index + start_pos] == '-')
			skip_chars = 2;
		node->value = strndup(str + *index + start_pos + skip_chars, cr_pos - skip_chars);
		//printf("value =%s=\n", node->value);
	}

	*index += cr_pos + start_pos;

    return node;
}

yaml_node *parse_yaml_string(char *yaml_str) {
    size_t index = 0;
    yaml_node *root = NULL, *current = NULL;
	size_t max = strlen(yaml_str);

    while (index < max) {
        yaml_node *new_node = parse_yaml_value(yaml_str, &index, &max);
        if (!root) {
            root = new_node;
            current = root;
        } else {
            current->next = new_node;
            current = new_node;
        }
    }

    return root;
}

void print_yaml_node(yaml_node *node) {
    if (node->key && node->value) {
        printf("%s: %s\n", node->key, node->value);
    } else if (node->key) {
        printf("%s:\n", node->key);
    } else {
        printf("%s\n", node->value);
    }
    if (node->next) {
        print_yaml_node(node->next);
    }
}

void parse_config_file(rist_tools_config_object *config, char *current_key, yaml_node *node) {
    if (node->key && !node->value) {
		if (current_key)
			free(current_key);
		current_key = strdup((char *) node->key);
        //printf("key node -> %s\n", node->key);
    } else if (node->key) {
		//printf("key/value node -> %s %s\n", node->key, node->value);
		current_key = strdup((char *) node->key);
		if (strcmp(current_key,"buffer") == 0) config->buffer=atoi((char *) node->value);
		else if (strcmp(current_key,"encryption-type") == 0) config->encryption_type=atoi((char *) node->value);
		else if (strcmp(current_key,"stats") == 0) config->stats_interval=atoi((char *) node->value);
		else if (strcmp(current_key,"verbose-level") == 0) config->verbose_level=atoi((char *) node->value);
		else if (strcmp(current_key,"profile") == 0) {
			if (strcmp((char *) node->value,"main") == 0) config->profile=1;
			else if (strcmp((char *) node->value,"advanced") == 0) config->profile=2;
			else if (strcmp((char *) node->value,"simple") == 0) config->profile=0;
			else config->profile=atoi((char *) node->value);
		}
		else if (strcmp(current_key,"remote-logging") == 0) strapp(&config->remote_log_address,(char *) node->value);
		else if (strcmp(current_key,"secret") == 0) strapp(&config->secret,(char *) node->value);
		else if (strcmp(current_key,"null-packet-deletion") == 0) config->null_packet_deletion=atoi((char *) node->value);
		else if (strcmp(current_key,"fast-start") == 0) config->fast_start=atoi((char *) node->value);
#ifdef USE_TUN
		else if (strcmp(current_key,"tun-mode") == 0) config->tun_mode=atoi((char *) node->value);
		else if (strcmp(current_key,"tun") == 0) strapp(&config->tunnel_interface,(char *) node->value);
#endif
#ifdef HAVE_SRP_SUPPORT
		else if (strcmp(current_key,"srpfile") == 0) strapp(&config->srp_file,(char *) node->value);
#endif
#ifdef HAVE_PROMETHEUS_SUPPORT
		else if (strcmp(current_key,"enable-metrics") == 0) config->enable_metrics=atoi((char *) node->value);
		else if (strcmp(current_key,"metrics-tags") == 0) strapp(&config->metrics_tags,(char *) node->value);
		else if (strcmp(current_key,"metrics-multipoint") == 0) config->metrics_multipoint=atoi((char *) node->value);
		else if (strcmp(current_key,"metrics-nocreated") == 0) config->metrics_nocreated=atoi((char *) node->value);
#ifdef HAVE_LIBMICROHTTPD
		else if (strcmp(current_key,"metrics-http") == 0) config->metrics_http=atoi((char *) node->value);
		else if (strcmp(current_key,"metrics-port") == 0) config->metrics_port=atoi((char *) node->value);
		else if (strcmp(current_key,"metrics-ip") == 0) strapp(&config->metrics_ip,(char *) node->value);
#endif
#if HAVE_SOCK_UN_H
		else if (strcmp(current_key,"metrics-unix") == 0) strapp(&config->metrics_unix,(char *) node->value);
#endif
#endif
	}
	else if (current_key)
	{
		if (strcmp(current_key,"inputurl") == 0)
		{
			strapp(&config->input_url,(char *) node->value);
			strapp(&config->input_url,",");
		}
		else if (strcmp(current_key,"outputurl") == 0)
		{
			strapp(&config->output_url,(char *) node->value);
			strapp(&config->output_url,",");
		}
        //printf("value node -> %s\n", node->value);
    }
	if (node->key)
		free(node->key);
	if (node->value)
		free(node->value);

    if (node->next) {
        parse_config_file(config, current_key, node->next);
		free(node);
    }
	else
	{
		// Remove trailing commas from aggregate URLs
		if (strlen(config->input_url) > 0) config->input_url[strlen(config->input_url)-1]=0;
		if (strlen(config->output_url) > 0) config->output_url[strlen(config->output_url)-1]=0;
		if (current_key)
			free(current_key);
		free(node);
	}
}

// Append to an exisitng string
void strapp(char ** original, char * newstr){
	if (*original){
		char * appended = malloc((strlen(newstr)+strlen(*original)+1)*sizeof(char));
		strcpy(appended,*original);
		strcat(appended,newstr);
		free(*original);
		*original = appended;
	} else {
		*original = strdup(newstr);
	}
}

// Function to parse yaml config into a rist_tools_config_object
rist_tools_config_object *parse_yaml(char * file){

	/*
	secret: blarg
	buffer: 0
	encryption-type: 256
	profile: <simple/main/advanced/#>
	stats: 1000
	inputurl:
	- <URL A>
	- <URL B>
	- ...
	outputurl:
	- <URL A>
	- <URL B>
	- ...
	*/

	rist_tools_config_object *config = NULL;

	// Open yaml file
	FILE *f = fopen(file,"r");
	if (f == NULL) return config;

	// Initialize rist_tools_config_object (non-zero values)
	config = calloc(1, sizeof(rist_tools_config_object));
	config->profile = RIST_PROFILE_MAIN;
	config->stats_interval = 1000;
	config->verbose_level = RIST_LOG_INFO;
#ifdef HAVE_PROMETHEUS_SUPPORT
#ifdef HAVE_LIBMICROHTTPD
		config->metrics_port = 1968;
#endif
#endif

	char *current_key = NULL;
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	fseek(f, 0, SEEK_SET);  /* same as rewind(f); */
	char *yaml_str = malloc(fsize + 1);
	size_t read = fread(yaml_str, fsize, 1, f);
	(void)read;
    yaml_node *root = parse_yaml_string(yaml_str);
	// print entire config file (debug)
    print_yaml_node(root);
	// transfer the data to the config structure
	parse_config_file(config, current_key, root);
	fclose(f);
	return config;
}

void cleanup_tools_config(rist_tools_config_object * config)
{
	if (config->remote_log_address)
        free(config->remote_log_address);
	if (config->secret)
        free(config->secret);
	if (config->input_url)
        free(config->input_url);
	if (config->output_url)
        free(config->output_url);
#ifdef USE_TUN
	if (config->tunnel_interface)
        free(config->tunnel_interface);
#endif
#ifdef HAVE_SRP_SUPPORT
	if (config->srp_file)
        free(config->srp_file);
#endif
#ifdef HAVE_PROMETHEUS_SUPPORT
	if (config->metrics_tags)
        free(config->metrics_tags);
#ifdef HAVE_LIBMICROHTTPD
	if (config->metrics_ip)
        free(config->metrics_ip);
#endif
#if HAVE_SOCK_UN_H
	if (config->metrics_unix)
        free(config->metrics_unix);
#endif
#endif
	free(config);
}
