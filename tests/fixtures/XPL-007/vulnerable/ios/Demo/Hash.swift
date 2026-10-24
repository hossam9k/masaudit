func signature(for payload: Data) -> Data {
    Data(Insecure.MD5.hash(data: payload))
}
