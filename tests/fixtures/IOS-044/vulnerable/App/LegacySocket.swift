import Darwin

func openLegacySocket(host: String) -> Int32 {
    let port: UInt16 = 80
    var hints = addrinfo()
    hints.ai_socktype = SOCK_STREAM
    var info: UnsafeMutablePointer<addrinfo>?
    guard getaddrinfo(host, String(port), &hints, &info) == 0, let first = info else { return -1 }
    let sock = socket(first.pointee.ai_family, first.pointee.ai_socktype, first.pointee.ai_protocol)
    _ = connect(sock, first.pointee.ai_addr, first.pointee.ai_addrlen)
    return sock
}
