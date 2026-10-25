import Network

// Near miss: the call spans lines and sets TLS 1.2; the TLS 1.0 mention below is a different call.
func modernParameters() -> NWParameters {
    let tlsOptions = NWProtocolTLS.Options()
    sec_protocol_options_set_min_tls_protocol_version(
        tlsOptions.securityProtocolOptions,
        .TLSv12
    )
    log(version: tls_protocol_version_t.TLSv10)
    return NWParameters(tls: tlsOptions)
}
