#include <ps4.h>
#include "ptrace.h"
#include "server.h"
#include "debug.h"
#include "protocol.h"

int _main(void) {
    initKernel();
    initLibc();
    initPthread();
    initNetwork();
    initSysUtil();

    // sleep a few seconds
    // maybe lower our thread priority?
    sceKernelSleep(2);

    // just a little notify
    char notifyBuffer[100];
    snprintf(notifyBuffer, sizeof(notifyBuffer), "Frame4 loaded!\nUpdate %s", PACKET_VERSION);
    sceSysUtilSendSystemNotificationWithText(222, notifyBuffer);

    // jailbreak current thread
    sys_console_cmd(SYS_CONSOLE_CMD_JAILBREAK, NULL);

    // updates
    mkdir("/update/PS4UPDATE.PUP", 0777);
    mkdir("/update/PS4UPDATE.PUP.net.temp", 0777);

    // create folders for scanner
    mkdir("/data/scan_temp", 0777);
    mkdir("/data/scan_temp/init", 0777);
    mkdir("/data/scan_temp/cur", 0777);
    mkdir("/data/scan_temp/old", 0777);

    // reconnect loop — survives rest mode
    int retry_count = 0;

    while (true) {
        if (!rest_network_is_up()) {
            if (retry_count == 0) {
                sceSysUtilSendSystemNotificationWithText(222, "Frame4: network down, waiting...");
            }
            retry_count++;
            sceKernelSleep(retry_count <= REST_SHORT_RETRY_MAX ? REST_SHORT_SLEEP_SEC : REST_LONG_SLEEP_SEC);
            continue;
        }

        // network is up — (re)launch all servers
        retry_count = 0;
        rest_mode_triggered = false;

        snprintf(notifyBuffer, sizeof(notifyBuffer), "Frame4 " PACKET_VERSION " server started");
        sceSysUtilSendSystemNotificationWithText(222, notifyBuffer);

    // start the http server
        ScePthread httpThread;
        scePthreadCreate(&httpThread, NULL, (void *)start_http, NULL, "http_server_thread");

    // start the uart socket
        ScePthread uartThread;
        scePthreadCreate(&uartThread, NULL, (void *)start_uart_server, NULL, "uart_server_thread");

        // start the socket server - blocks until unload or rest mode
    start_server();

        if (!rest_mode_triggered)
            break; // normal unload, exit for real

        // rest mode: wait for threads to finish, then loop back
        uprintf("rest mode: waiting for network to return...");
        sceKernelSleep(REST_SHORT_SLEEP_SEC);
    }

    return 0;
}
