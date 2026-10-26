// The C Network.framework API with TLS turned off, to a public host.
#import <Network/Network.h>

nw_connection_t OpenTelemetry(void) {
    nw_endpoint_t endpoint = nw_endpoint_create_host("telemetry.example.com", "9000");
    nw_parameters_t params = nw_parameters_create_secure_tcp(NW_PARAMETERS_DISABLE_PROTOCOL,
                                                             NW_PARAMETERS_DEFAULT_CONFIGURATION);
    return nw_connection_create(endpoint, params);
}
