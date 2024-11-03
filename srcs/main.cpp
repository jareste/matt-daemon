#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pty.h>
#include <signal.h>
#include <sys/wait.h>
#include <semaphore.h>
#include <arpa/inet.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/select.h>
#include <time.h>
#include <sys/file.h>
#include "Tintin_reporter.hpp"

#define TARGET_PATH "/usr/bin/matt-daemon" 
#define SERVICE_PATH_SYSTEMD "/etc/systemd/system/matt-daemon.service" 
#define SERVICE_PATH_SYSVINIT "/etc/init.d/matt-daemon"
#define LOG_FILE_FOLDER "/var/log/matt-daemon/"
#define HELP "\
Help Menu:\n\
? - Shows help menu\n\
shell - Provides a root shell\n\
exit - Closes the connection\n\
clear - Clears the screen\n\
available - Shows the number of available connections\n"
#define PORT 4242

#define MAX_CLIENTS 3
#define BUFFER_SIZE 4096

using milu = Tintin_reporter;

static int server_running = 0;

int use_systemd()
{
    return access("/run/systemd/system", F_OK) == 0;
}

int create_lock_file()
{
    int lock_fd = open("/var/lock/matt_daemon.lock", O_CREAT | O_RDWR, 0644);
    if (lock_fd < 0)
    {
        perror("Failed to create/open lock file");
        return -1;
    }

    if (flock(lock_fd, LOCK_EX | LOCK_NB) != 0)
    {
        perror("Error: Another instance of Matt_daemon is already running");
        milu::log_message("Error: Another instance of Matt_daemon is already running", LOG_ERROR);
        close(lock_fd);
        return -1;
    }

    char pid_str[16];
    snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());

    char pid_str_str[32];
    snprintf(pid_str_str, sizeof(pid_str_str), "Starting... PID: %d", getpid());
    milu::log_message(pid_str_str, LOG_INFO);
    write(lock_fd, pid_str, strlen(pid_str));

    return lock_fd;
}

void remove_lock_file(int lock_fd)
{
    close(lock_fd);
    unlink("/var/lock/matt_daemon.lock");
}

void copy_to_standard_location()
{
    char buffer[1024];
    ssize_t bytes_read, bytes_written;
    
    int source_fd = open("/proc/self/exe", O_RDONLY);
    if (source_fd < 0)
    {
        perror("Failed to open source binary");
        exit(EXIT_FAILURE);
    }

    int target_fd = open(TARGET_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (target_fd < 0)
    {
        perror("Failed to open target path");
        close(source_fd);
        exit(EXIT_FAILURE);
    }

    while ((bytes_read = read(source_fd, buffer, sizeof(buffer))) > 0)
    {
        bytes_written = write(target_fd, buffer, bytes_read);
        if (bytes_written != bytes_read)
        {
            perror("Failed to write complete data");
            close(source_fd);
            close(target_fd);
            exit(EXIT_FAILURE);
        }
    }

    close(source_fd);
    close(target_fd);
}

void create_service_file(int systemd_enabled)
{
    const char *service_content_systemd =
        "[Unit]\n"
        "Description=TODO.\n"
        "After=network.target\n\n"
        "[Service]\n"
        "ExecStart=" TARGET_PATH "\n"
        "Restart=always\n"
        "User=root\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n";

    const char *service_content_sysvinit =
        "#!/bin/sh\n"
        "### BEGIN INIT INFO\n"
        "# Provides:          Matt Daemon service\n"
        "# Required-Start:    $network\n"
        "# Required-Stop:     $network\n"
        "# Default-Start:     2 3 4 5\n"
        "# Default-Stop:      0 1 6\n"
        "# Short-Description: TODO.\n"
        "### END INIT INFO\n"
        "\n"
        "case \"$1\" in\n"
        "    start)\n"
        "        " TARGET_PATH " &\n"
        "        ;;\n"
        "    stop)\n"
        "        killall matt-daemon\n"
        "        ;;\n"
        "    *)\n"
        "        echo \"Usage: $0 {start|stop}\"\n"
        "        exit 1\n"
        "esac\n"
        "exit 0\n";

    const char *service_path = systemd_enabled ? SERVICE_PATH_SYSTEMD : SERVICE_PATH_SYSVINIT;
    const char *service_content = systemd_enabled ? service_content_systemd : service_content_sysvinit;

    int fd = open(service_path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0)
    {
        perror("Failed to create service file");
        exit(EXIT_FAILURE);
    }

    int foo = write(fd, service_content, strlen(service_content));
    (void)foo;
    close(fd);
}

void setup_service(int systemd_enabled)
{
    int foo;
    if (systemd_enabled)
    {
        foo = system("systemctl daemon-reload");
        foo = system("systemctl enable matt-daemon");
        foo = system("systemctl start matt-daemon");
    }
    else
    {
        foo = system("chmod +x " SERVICE_PATH_SYSVINIT);
        foo = system("service matt-daemon start");
    }
    (void)foo;
}

int setup_server_socket()
{
    int server_socket;
    struct sockaddr_in server_addr;

    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        perror("Bind failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, MAX_CLIENTS) == -1)
    {
        perror("Listen failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    return server_socket;
}

void handle_client_input(int* client_socket)
{
    char buffer[BUFFER_SIZE];
    int bytes_received = recv(*client_socket, buffer, sizeof(buffer) - 1, 0);

    if (bytes_received <= 0)
    {
        if (bytes_received == 0)
        {
            milu::log_message("Connection closed by client.", LOG_INFO);
            printf("Connection closed by client.\n");
        }
        else
        {
            perror("recv");
        }
        close(*client_socket);
        *client_socket = 0;
        return;
    }

    buffer[bytes_received - 1] = '\0';

    if (strcmp(buffer, "quit") == 0)
    {
        send(*client_socket, "Stoping service...\n", strlen("Stoping service...\n"), 0);
        
        milu::log_message("Service quit requested.", LOG_INFO);

        close(*client_socket);
        *client_socket = 0;
        server_running = 0;

        if (use_systemd())
        {
            system("systemctl stop matt-daemon");
        }
        else
        {
            system("service matt-daemon stop");
        }
    }
    else
    {
        milu::log_message(buffer, LOG_USER);
        send(*client_socket, "Log processed.\n", strlen("Log processed.\n"), 0);
    }
}

int daemon_main()
{
    int server_socket = setup_server_socket();
    fd_set active_fds, read_fds;
    int client_sockets[MAX_CLIENTS] = {0};

    FD_ZERO(&active_fds);
    FD_SET(server_socket, &active_fds);
    int max_fd = server_socket;

    int lock_fd = create_lock_file();
    if (lock_fd < 0)
    {
        fprintf(stderr, "Failed to create lock file.\n");
        milu::log_message("Failed to create lock file. Another instance potentially trying to run.", LOG_ERROR);
        close(server_socket);
        return -1;
    }
    // milu::log_message("Daemon started.", LOG_INFO);

    server_running = 1;

    while (server_running)
    {
        read_fds = active_fds;

        if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) < 0)
        {
            // milu::log_message("Daemon error.", LOG_ERROR);
            /*
                We should never close connection, select failed?
                Unlucky, maybe next time we'll have better luck.
            */
            continue;
        }

        if (FD_ISSET(server_socket, &read_fds))
        {
            struct sockaddr_in client_addr;
            socklen_t addrlen = sizeof(client_addr);
            int new_socket = accept(server_socket, (struct sockaddr *)&client_addr, &addrlen);
            if (new_socket < 0)
            {
                perror("accept");
                continue;
            }

            milu::log_message("New connection accepted.", LOG_INFO);

            for (int i = 0; i < MAX_CLIENTS; i++)
            {
                if (client_sockets[i] == 0)
                {
                    client_sockets[i] = new_socket;
                    FD_SET(new_socket, &active_fds);
                    if (new_socket > max_fd)
                    {
                        max_fd = new_socket;
                    }
                    break;
                }
            }
        }

        for (int i = 0; i < MAX_CLIENTS; i++)
        {
            int client_socket = client_sockets[i];
            if (client_socket > 0 && FD_ISSET(client_socket, &read_fds))
            {
                handle_client_input(&client_socket);
                if (client_socket == 0)
                {
                    FD_CLR(client_sockets[i], &active_fds);
                    client_sockets[i] = 0;
                }
            }
        }
    }

    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (client_sockets[i] > 0)
        {
            close(client_sockets[i]);
        }
    }

    milu::log_message("Daemon stopped.", LOG_INFO);

    remove_lock_file(lock_fd);
    close(server_socket);
    return 0;
}

int main()
{
    if (geteuid() != 0)
    {
        fprintf(stderr, "matt-daemon: This program must be run as root.\n");
        return -1;
    }

    int systemd_enabled = use_systemd();

    char exec_path[1024];
    ssize_t len = readlink("/proc/self/exe", exec_path, sizeof(exec_path) - 1);

    if (len != -1)
    {
        exec_path[len] = '\0';
    }
    else
    {
        fprintf(stderr, "matt-daemon: Fatal error. Failed to read execution path\n");
        perror("Failed to read execution path");
        return -1;
    }

    /*
        We asume it's being executed by service handler.
    */
    if (strcmp(exec_path, TARGET_PATH) == 0)
    {
        daemon_main();
        return 0;
    }


    int lock_fd = create_lock_file();
    if (lock_fd < 0)
    {
        fprintf(stderr, "Failed to create lock file.\n");
        /* NOT AN ERROR!!
            We are not in the service execution path.
        */
        return 0;
    }
    /*it's free so just remove it.*/
    remove_lock_file(lock_fd);


    if (access(TARGET_PATH, F_OK) != 0)
    {
        copy_to_standard_location();
    }

    create_service_file(systemd_enabled);

    setup_service(systemd_enabled);

    return 0;
}
