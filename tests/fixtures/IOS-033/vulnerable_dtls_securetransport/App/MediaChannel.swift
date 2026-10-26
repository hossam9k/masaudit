// Vulnerable: DTLS options for a UDP media channel accept DTLS 1.0 (the TLS 1.1 equivalent).
import Network

func mediaParameters() -> NWParameters {
    let dtls = NWProtocolTLS.Options()
    sec_protocol_options_set_min_tls_protocol_version(dtls.securityProtocolOptions, .DTLSv10)
    return NWParameters(dtls: dtls)
}
