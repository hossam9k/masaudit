// Near miss: DTLS 1.2 is the floor for the UDP media channel.
import Network

func mediaParameters() -> NWParameters {
    let dtls = NWProtocolTLS.Options()
    sec_protocol_options_set_min_tls_protocol_version(dtls.securityProtocolOptions, .DTLSv12)
    return NWParameters(dtls: dtls)
}
