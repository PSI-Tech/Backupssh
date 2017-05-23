#include <ssh.h>

ssh_session create_ssh_session(const char *host, int verbosity, int port)
{
	ssh_session session = ssh_new();
	if(session == NULL)
		return NULL;
	ssh_options_set(session, SSH_OPTIONS_HOST, host);
	ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
	ssh_options_set(session, SSH_OPTIONS_PORT, &port);

	return session;
}

int verify_ssh_host(ssh_session session)
{
	int hlen;
	unsigned char *hash = NULL;
	char *hexa;
	char buf[10];

	hlen = ssh_get_pubkey_hash(session, &hash);
	if(hlen < 0)
		return -1; /* TODO: Error codes */
	return 0;
}
