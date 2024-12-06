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
#define LOG_FILE_FOLDER_REMOVE "/var/log/matt-daemon/*"
#define LOG_FILE "/var/log/matt-daemon/matt_daemon.log"
#define LOCK_FILE_PATH "/var/lock/matt_daemon.lock"
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

#define SEM_NAME "/matias_el_semaforos"
#define SEM_WRITE_NAME "/matias_el_semaforos_write"

#define SEND_MSG_START  sem_wait(sem_write);
#define SEND_MSG_END    sem_post(sem_write);

#define SEND_SAFE_MSG(x,y) sem_wait(&sem_write); milu::log_message(x, y); sem_post(&sem_write);
/*
 * Unsafe should not be used never, but we assume that there will not be
 * any concurrency issues in this case. And, if there are, it is not a big deal.
 */
#define SEND_UNSAFE_MSG(x,y) milu::log_message(x, y);

#define CHILD_EXIT_CODE_EXIT 42

using milu = Tintin_reporter;

static int server_running;

sem_t sem;
sem_t sem_write;
sem_t sem_encrypt;

char *read_file(const char *file_path)
{

    FILE *file = fopen(file_path, "rb");
    if (!file) return NULL;

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *content = (char*)malloc(file_size + 1);
    
    fread(content, 1, file_size, file);
    content[file_size] = '\0';
    fclose(file);
    return content;
}

int write_file(const char *file_path, const char *content)
{
    FILE *file = fopen(file_path, "wb");
    if (!file) return -1;

    fwrite(content, 1, strlen(content), file);
    fclose(file);
    return 0;
}

void encrypt_log_file(const char *file_path)
{
    char *content = read_file(file_path);
    if (!content)
        return;

    size_t content_len = strlen(content);
    size_t base64_len = 4 * ((content_len + 2) / 3);

    char *base64_content = (char*)malloc(base64_len + 1);
 
    size_t index = 0;
    const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0;
    while (i < content_len)
    {
        uint32_t octet_a = i < content_len ? (unsigned char)content[i++] : 0;
        uint32_t octet_b = i < content_len ? (unsigned char)content[i++] : 0;
        uint32_t octet_c = i < content_len ? (unsigned char)content[i++] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        base64_content[index++] = base64_chars[(triple >> 18) & 0x3F];
        base64_content[index++] = base64_chars[(triple >> 12) & 0x3F];
        base64_content[index++] = base64_chars[(triple >> 6) & 0x3F];
        base64_content[index++] = base64_chars[triple & 0x3F];
    }
    for (size_t j = 0; j < (base64_len - index); ++j)
        base64_content[index + j] = '=';

    base64_content[base64_len] = '\0';
    write_file(file_path, base64_content);
 
    free(content);
    free(base64_content);
}

void decrypt_log_file(const char *file_path)
{
    char *content = read_file(file_path);
    if (!content)
        return;

    size_t content_len = strlen(content);
    size_t decoded_len = content_len * 3 / 4;
    if (content[content_len - 1] == '=')
    {
        decoded_len--;
        if (content[content_len - 2] == '=')
            decoded_len--;
    }

    char *decoded_content = (char*)malloc(decoded_len + 1);

    size_t i = 0;
    size_t j = 0;
    while (i < content_len)
    {
        uint32_t triple = 0;
        for (int k = 0; k < 4; k++)
        {
            triple <<= 6;
            if (content[i] >= 'A' && content[i] <= 'Z')
                triple |= content[i] - 'A';
            else if (content[i] >= 'a' && content[i] <= 'z')
                triple |= content[i] - 'a' + 26;
            else if (content[i] >= '0' && content[i] <= '9')
                triple |= content[i] - '0' + 52;
            else if (content[i] == '+')
                triple |= 62;
            else if (content[i] == '/')
                triple |= 63;
            else if (content[i] == '=')
                triple |= 0;
            i++;
        }

        decoded_content[j++] = (triple >> 16) & 0xFF;
        if (i < content_len)
            decoded_content[j++] = (triple >> 8) & 0xFF;
        if (i < content_len)
            decoded_content[j++] = triple & 0xFF;
    }

    decoded_content[decoded_len] = '\0';

    write_file(file_path, decoded_content);

    free(content);
    free(decoded_content);
}

int use_systemd()
{
    return access("/run/systemd/system", F_OK) == 0;
}

int create_lock_file(int log)
{
    int lock_fd = open(LOCK_FILE_PATH, O_CREAT | O_RDWR, 0644);
    if (lock_fd < 0)
    {
        perror("Failed to create/open lock file");
        return -1;
    }

    if (flock(lock_fd, LOCK_EX | LOCK_NB) != 0)
    {
        SEND_UNSAFE_MSG("Error: Another instance of Matt_daemon is already running", LOG_ERROR);
        close(lock_fd);
        return -1;
    }

    char pid_str[16];
    snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());

    if (log == 1)
    {
        char pid_str_str[32];
        snprintf(pid_str_str, sizeof(pid_str_str), "Starting... PID: %d", getpid());
        SEND_UNSAFE_MSG(pid_str_str, LOG_INFO);
    }    
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

    fprintf(stderr, "Setting up server socket.\n");
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        fprintf(stderr, "Socket failed\n");
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
        fprintf(stderr, "Bind failed\n");
        perror("Bind failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, MAX_CLIENTS) == -1)
    {
        fprintf(stderr, "Listen failed\n");
        perror("Listen failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "Server socket setup complete.\n");
    return server_socket;
}

int handle_client(int client_socket, const char* client_ip)
{
    char buffer[BUFFER_SIZE];

    snprintf(buffer, sizeof(buffer), "Connection from %s received.", client_ip);

    SEND_SAFE_MSG(buffer, LOG_INFO);
    memset(buffer, 0, sizeof(buffer));

    while (1)
    {
        int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received <= 0)
        {
            if (bytes_received == 0)
            {
                snprintf(buffer, sizeof(buffer), "Connection closed by client %s .", client_ip);
                SEND_SAFE_MSG(buffer, LOG_INFO);

            }
            else
            {
                snprintf(buffer, sizeof(buffer), "Unknown error on client %s . Closing connection", client_ip);
                SEND_SAFE_MSG(buffer, LOG_ERROR);
            }
            close(client_socket);
            client_socket = 0;
            break;
        }

        buffer[bytes_received - 1] = '\0';

        int sem_value;
        sem_getvalue(&sem_encrypt, &sem_value);

        if (strcmp(buffer, "save") != 0 && sem_value == 0)
        {
            decrypt_log_file(LOG_FILE);
            sem_post(&sem_encrypt);
            sem_getvalue(&sem_encrypt, &sem_value);
        }

        if (strcmp(buffer, "quit") == 0)
        {
            send(client_socket, "Stoping service...\n", strlen("Stoping service...\n"), 0);
            SEND_SAFE_MSG("Service quit requested.", LOG_INFO);

            close(client_socket);
            client_socket = 0;
            return CHILD_EXIT_CODE_EXIT;

            // if (use_systemd())
            // {
            //     system("systemctl stop matt-daemon");
            // }
            // else
            // {
            //     system("service matt-daemon stop");
            // }
        }
        else if (strcmp(buffer, "encrypt") == 0 && sem_value == 1)
        {
            encrypt_log_file(LOG_FILE);
            sem_wait(&sem_encrypt);
            send(client_socket, "Encrypted successfully.\n", strlen("Encrypted successfully.\n"), 0);
        }
        else if (strcmp(buffer, "decrypt") == 0)
        {
            if (sem_value == 0)
            {
                send(client_socket, "Log already decrypted.\n", strlen("Log already decrypted.\n"), 0);
                continue;
            }
            decrypt_log_file(LOG_FILE);
            sem_post(&sem_encrypt);
            send(client_socket, "Decrypted successfully.\n", strlen("Decrypted successfully.\n"), 0);
        }
        else if (strcmp(buffer, "clear-all") == 0)
        {
            system("rm -rf " LOG_FILE_FOLDER_REMOVE);
            send(client_socket, "All logs removed.\n", strlen("All logs removed.\n"), 0);
        }
        else if (strcmp(buffer, "save") == 0)
        {
            char system_instruction[300] = {0};
            char new_log_file[200] = {0};

            time_t now = time(NULL);
            struct tm *t = localtime(&now);
            strftime(new_log_file, sizeof(new_log_file) - 1, "/var/log/matt-daemon/matt_daemon_%Y%m%d_%H%M%S.log", t);

            sprintf(system_instruction, "mv %s %s", LOG_FILE, new_log_file);
            system(system_instruction);

            snprintf(buffer, sizeof(buffer), "File saved as %s\n", new_log_file);
            sem_post(&sem_encrypt);
            send(client_socket, buffer, strlen(buffer), 0);
        }
        else
        {
            SEND_SAFE_MSG(buffer, LOG_USER);
            send(client_socket, "Log processed.\n", strlen("Log processed.\n"), 0);
        }
    }
    return EXIT_SUCCESS;
}

void handle_sigchld(int sig)
{
    (void)sig;
    int status;
    while (waitpid(-1, &status, WNOHANG) > 0)
    {
        if (WIFEXITED(status) && WEXITSTATUS(status) == CHILD_EXIT_CODE_EXIT)
        {
            server_running = 0;
        }
        sem_post(&sem);
    }
}

int daemon_main()
{
    int server_socket, client_socket;    
    struct sockaddr_in client_addr;
    socklen_t client_addr_size = sizeof(client_addr);

    server_socket = setup_server_socket();

    sem_init(&sem, 0, 3);
    sem_init(&sem_write, 0, 1);
    sem_init(&sem_encrypt, 0, 1);

    int lock_fd = create_lock_file(1);
    if (lock_fd < 0)
    {
        SEND_SAFE_MSG("Failed to create lock file. Another instance potentially trying to run.", LOG_ERROR);
        close(server_socket);
        return -1;
    }

    struct sigaction sa;
    sa.sa_handler = handle_sigchld;
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);

    server_running = 1;

    while (server_running)
    {
        sem_wait(&sem);

        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_size);
        if (client_socket == -1)
        {
            SEND_SAFE_MSG("Incomming connection refused due to: Accept Failed.", LOG_ERROR);

            sem_post(&sem);
            continue;
        }
        if (fork() == 0)
        {
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

            int foo = handle_client(client_socket, client_ip);
            close(server_socket);
            exit(foo);
        }
        close(client_socket);
    }

    SEND_SAFE_MSG("Daemon stopped.", LOG_INFO);

    remove_lock_file(lock_fd);
    sem_destroy(&sem);
    sem_destroy(&sem_write);
    close(lock_fd);
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

    int lock_fd;
    char exec_path[1024];
    ssize_t len = readlink("/proc/self/exe", exec_path, sizeof(exec_path) - 1);

    if (len != -1)
    {
        exec_path[len] = '\0';
    }
    else
    {
        fprintf(stderr, "matt-daemon: Fatal error. Failed to read execution path.\n");
        return -1;
    }

    if (strcmp(exec_path, TARGET_PATH) == 0)
    {
        goto daemon_setup;
    }


    lock_fd = create_lock_file(0);
    if (lock_fd < 0)
    {
        fprintf(stderr, "Failed to create lock file.\n");
        return 0;
    }
    remove_lock_file(lock_fd);

daemon_setup:
    pid_t pid = fork();

    if (pid < 0) return 1;

    if (pid > 0) return 0;

    if (setsid() < 0) return 1;

    pid = fork();

    if (pid < 0) return 1;

    if (pid > 0) return 0;

    umask(0);
    chdir("/");

    for (int x = sysconf(_SC_OPEN_MAX); x >= 0; x--)
        close(x);

    open("/dev/null", O_RDWR);
    dup(0);
    dup(0);

    prctl(PR_SET_PDEATHSIG, SIGKILL);

    daemon_main();

    return 0;
}
