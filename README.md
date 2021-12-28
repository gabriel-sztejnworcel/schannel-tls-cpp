# schannel-tls-cpp
schannel-tls-cpp is a TLS client/server library for Windows that uses Windows' built-in TLS implementation (schannel).

### Server Sample
```cpp
schannel::TLSConfig tls_config;

// Only TLS 1.2 or TLS 1.3
tls_config.enabled_protocols = SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER;

// Get the certificate from the local user personal certificate store
tls_config.cert_store_location = CERT_SYSTEM_STORE_CURRENT_USER;
tls_config.cert_store_name = "My";
tls_config.cert_subject_match = "gabriel-sztejnworcel.com";

// Create the server object and start listening
schannel::TLSServer tls_server(tls_config);
tls_server.listen("localhost", 8443);

// Wait for and accept a client connection
auto tls_socket = tls_server.accept();

// Receive and decrypt
int bytes = tls_socket.recv();

// Build a string from the decrypted buffer (stored in the tls socket object)
std::string msg(tls_socket.decrypted_buffer(), bytes);

std::cout << "Received: " << msg << std::endl;
```

### Client Sample
```cpp
schannel::TLSConfig tls_config;

// Only TLS 1.2 or TLS 1.3
tls_config.enabled_protocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT;

// Skip server certificate verification (should be used only in dev/debug)
tls_config.verify_server_cert = false;

// Create the client object
schannel::TLSClient tls_client(tls_config);

// Connect to the server (including the TLS handshake)
auto tls_socket = tls_client.connect("localhost", 8443);

// Send a message to the server
std::string msg = "Hello World";
tls_socket.send(msg.c_str(), (int)msg.length());
```
