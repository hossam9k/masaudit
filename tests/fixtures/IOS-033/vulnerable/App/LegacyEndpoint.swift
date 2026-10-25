import Network

func legacyParameters() -> NWParameters {
    let tlsOptions = NWProtocolTLS.Options()
    sec_protocol_options_set_min_tls_protocol_version(
        tlsOptions.securityProtocolOptions,
        .TLSv10
    )
    return NWParameters(tls: tlsOptions)
}
