import Network

func makeParams() -> NWParameters {
    let tls = NWProtocolTLS.Options()
    sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv10)
    sec_protocol_options_set_max_tls_protocol_version(tls.securityProtocolOptions, tls_protocol_version_t.TLSv11)
    return NWParameters(tls: tls)
}
