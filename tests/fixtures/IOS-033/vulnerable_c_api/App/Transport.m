// The C Network.framework API, all lowercase, plus its deprecated SSLProtocol setter.
#import <Network/Network.h>

nw_parameters_t LegacyParameters(void) {
    return nw_parameters_create_secure_tcp(^(nw_protocol_options_t tls) {
        sec_protocol_options_t sec = nw_tls_copy_sec_protocol_options(tls);
        sec_protocol_options_set_min_tls_protocol_version(sec, tls_protocol_version_TLSv11);
        sec_protocol_options_set_tls_min_version(sec, kTLSProtocol1);
    }, NW_PARAMETERS_DEFAULT_CONFIGURATION);
}
