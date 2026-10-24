package com.acme.app;

class Sock {
    Object read(Socket socket) throws Exception {
        return new ObjectInputStream(socket.getInputStream()).readObject();
    }

    Object poll(Socket socket) throws Exception {
        return read(socket);
    }
}
