/* librist. Copyright © 2024 SipRadius LLC. All right reserved.
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "config.h"
#include "librist_config.h"

typedef struct rist_tools_config_object {
        int buffer;
        int encryption_type;
        int profile;
        int stats_interval;
        int verbose_level;        
        char * remote_log_address;
        char * secret;
        char * input_url;
        char * output_url;
        int null_packet_deletion;
        int fast_start;
#ifdef USE_TUN
        char * tunnel_interface;
        int tun_mode;
#endif
#ifdef HAVE_SRP_SUPPORT
        char * srp_file;
#endif
#ifdef HAVE_PROMETHEUS_SUPPORT
        int enable_metrics;
        char * metrics_tags;
        int metrics_multipoint;
        int metrics_nocreated;
#ifdef HAVE_LIBMICROHTTPD
        int metrics_http;
        int metrics_port;
        char * metrics_ip;
#endif
#if HAVE_SOCK_UN_H
        char * metrics_unix;
#endif
#endif
} rist_tools_config_object;

typedef struct yaml_node {
    char *key;
    char *value;
    struct yaml_node *next;
} yaml_node;

#ifndef strndup
char *strndup (const char *str, size_t max);
#endif
size_t rist_findchar(const char* str, int c, size_t max);
yaml_node *parse_yaml_value(char *str, size_t *index, size_t *max);
yaml_node *parse_yaml_string(char *yaml_str);
void print_yaml_node(yaml_node *node);
void parse_config_file(rist_tools_config_object *config, char *current_key, yaml_node *node);
void strapp(char ** original, char * newstr);
rist_tools_config_object *parse_yaml(char * file);
void cleanup_tools_config(rist_tools_config_object * config);
