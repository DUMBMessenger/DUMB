#include <iostream>
#include <vector>
#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <algorithm>

std::vector<int> clients;

void broadcast(const std::string& message, int exclude_fd = -1) {
    for (int client : clients) {
        if (client != exclude_fd) {
            send(client, message.c_str(), message.size(), 0);
        }
    }
}

void handle_client(int client_socket) {
    char username[256] = {0};
    int bytes = recv(client_socket, username, sizeof(username)-1, 0);
    if (bytes <= 0) {
        close(client_socket);
        return;
    }

    std::string join_msg = "[" + std::string(username) + " подключился]";
    std::cout << join_msg << std::endl;
    broadcast(join_msg, client_socket);

    char buffer[1024];
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        bytes = recv(client_socket, buffer, sizeof(buffer)-1, 0);
        if (bytes <= 0) {
            break;
        }

        std::string msg = std::string(username) + ": " + buffer;
        std::cout << msg << std::endl;
        broadcast(msg, client_socket);
    }

    std::string leave_msg = "[" + std::string(username) + " вышел]";
    std::cout << leave_msg << std::endl;
    broadcast(leave_msg);

    close(client_socket);
    clients.erase(std::remove(clients.begin(), clients.end(), client_socket), clients.end());
}

int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8080);

    bind(server_fd, (sockaddr*)&address, sizeof(address));
    listen(server_fd, 5);

    std::cout << "Сервер запущен на порту 8080\n";

    while (true) {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int client_socket = accept(server_fd, (sockaddr*)&client_addr, &client_len);

        clients.push_back(client_socket);
        std::thread(handle_client, client_socket).detach();
    }

    close(server_fd);
    return 0;
}
