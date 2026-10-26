// The C Network.framework API, all lowercase, with a TLS 1.2 floor.
#import <Network/Network.h>

nw_parameters_t LegacyParameters(void) {
    return nw_parameters_create_secure_tcp(^(nw_protocol_options_t tls) {
        sec_protocol_options_t sec = nw_tls_copy_sec_protocol_options(tls);
        sec_protocol_options_set_min_tls_protocol_version(sec, tls_protocol_version_TLSv12);
        sec_protocol_options_set_tls_min_version(sec, kTLSProtocol12);
    }, NW_PARAMETERS_DEFAULT_CONFIGURATION);
}
