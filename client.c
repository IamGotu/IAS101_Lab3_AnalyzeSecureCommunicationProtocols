#include <stdio.h>
#include <winsock2.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#define HOST "127.0.0.1"
#define PORT 4433

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX* create_context() {
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);

    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Force TLS 1.3 only
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    return ctx;
}

int main() {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in addr;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    init_openssl();
    SSL_CTX* ctx = create_context();

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        printf("Socket creation failed\n");
        return 1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr(HOST);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr))) {
        printf("Connection failed\n");
        return 1;
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    }
    else {
        printf("TLS 1.3 handshake successful!\n");
        printf("Cipher: %s\n", SSL_get_cipher(ssl));

        const char* msg = "Hello TLS 1.3 from Windows!";
        SSL_write(ssl, msg, strlen(msg));

        char buf[1024];
        int bytes = SSL_read(ssl, buf, sizeof(buf));
        if (bytes > 0) {
            printf("Received: %.*s\n", bytes, buf);
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    WSACleanup();

    return 0;
}