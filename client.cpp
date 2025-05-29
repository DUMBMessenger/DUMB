#include <iostream>
#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

void receive_messages(int sock) {
    char buffer[1024];
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int bytes = recv(sock, buffer, sizeof(buffer)-1, 0);
        if (bytes <= 0) {
            std::cout << "Соединение с сервером потеряно\n";
            exit(0);
        }
        std::cout << buffer << std::endl;
    }
}

int main() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Ошибка создания сокета\n";
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8080);
    inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);

    if (connect(sock, (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Ошибка подключения\n";
        return 1;
    }

    std::string username;
    std::cout << "Введите ваше имя: ";
    std::getline(std::cin, username);
    send(sock, username.c_str(), username.size(), 0);

    std::thread(receive_messages, sock).detach();

    std::cout << "Добро пожаловать в чат! (Для выхода введите /exit)\n";

    while (true) {
        std::string message;
        std::getline(std::cin, message);

        if (message == "/exit") {
            break;
        }

        if (send(sock, message.c_str(), message.size(), 0) < 0) {
            std::cerr << "Ошибка отправки\n";
            break;
        }
    }

    close(sock);
    return 0;
}
