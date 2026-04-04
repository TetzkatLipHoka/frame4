#ifndef _SERVER_H
#define _SERVER_H

#include <ps4.h>
#include "protocol.h"
#include "net.h"

#include "proc.h"
#include "debug.h"
#include "kern.h"
#include "console.h"

#define SOCK_SERVER_PORT        2811
#define UART_SERVER_PORT        3321
#define HTTP_SERVER_PORT        2812
#define SERVER_MAXCLIENTS       8
#define UART_SERVER_MAXCLIENTS  1

#define BROADCAST_SERVER_PORT   2813
#define BROADCAST_MAGIC         0xFFFFAAAA

/* Rest mode support */
#define REST_ECONNABORTED_PS4   163     /* PS4 kernel rest mode errno */
#define REST_SHORT_RETRY_MAX    99      /* short-sleep retry count before backoff */
#define REST_SHORT_SLEEP_SEC    2       /* sleep between retries while polling */
#define REST_LONG_SLEEP_SEC     1000    /* sleep after many failed retries */

extern bool rest_mode_triggered;

int  rest_network_is_up(void);
void rest_teardown_servers(void);

extern struct server_client servclients[SERVER_MAXCLIENTS];
extern struct uart_server_client uartservclients[UART_SERVER_MAXCLIENTS];

struct server_client *alloc_client();
void free_client(struct server_client *svc);

struct uart_server_client *alloc_uart_client();
void free_uart_client(struct uart_server_client *svc);

int handle_version(int fd, struct cmd_packet *packet);
int cmd_handler(int fd, struct cmd_packet *packet);
int check_debug_interrupt();
int handle_socket_client(struct server_client *svc);
void handle_web_client(int fd);

void configure_socket(int fd);
void *broadcast_thread(void *arg);
int start_server();
int start_http();
int start_uart_server();

#endif
