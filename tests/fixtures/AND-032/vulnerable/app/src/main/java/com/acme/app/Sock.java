package com.acme.app;

class Sock {
    Object read(Socket socket) throws Exception {
        return new ObjectInputStream(socket.getInputStream()).readObject();
    }
}
