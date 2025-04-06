#include <stdio.h>
#include <winsock2.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#define PORT 4433
#define CERT_FILE "server.crt"
#define KEY_FILE "server.key"

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX* create_context() {
    const SSL_METHOD* method = TLS_server_method();
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

void configure_context(SSL_CTX* ctx) {
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int main() {
    WSADATA wsaData;
    SOCKET sock, client;
    struct sockaddr_in addr;

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    // Initialize OpenSSL
    init_openssl();
    SSL_CTX *ctx = create_context();
    configure_context(ctx);

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        printf("Socket creation failed\n");
        return 1;
    }

    // Bind socket
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {  // FIXED LINE
        printf("Bind failed\n");
        return 1;
    }

    // Listen and accept connections
    if (listen(sock, 1) < 0) {
        printf("Listen failed\n");
        return 1;
    }

    printf("Server listening on port %d...\n", PORT);

    while (1) {
        int addrlen = sizeof(addr);
        client = accept(sock, (struct sockaddr*)&addr, &addrlen);
        if (client == INVALID_SOCKET) {
            printf("Accept failed\n");
            continue;
        }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            printf("TLS 1.3 handshake successful!\n");
            printf("Cipher: %s\n", SSL_get_cipher(ssl));

            char buf[1024];
            int bytes = SSL_read(ssl, buf, sizeof(buf));
            if (bytes > 0) {
                SSL_write(ssl, buf, bytes);
            }
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        closesocket(client);
    }

    closesocket(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    WSACleanup();
    return 0;
}