#include <ssh.h>
#include <error.h>
#include <stdio.h>
#include <string.h>

ssh_session create_ssh_session(int *err, const char *host, int verbosity, int port)
{
	ssh_session session = ssh_new();
	if(session == NULL)
		return NULL;
	ssh_options_set(session, SSH_OPTIONS_HOST, host);
	ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
	ssh_options_set(session, SSH_OPTIONS_PORT, &port);

	*err = BACKUPSSH_SUCCESS;
	return session;
}

int verify_ssh_host(ssh_session session)
{
	int err;
	ssh_key key;
	size_t hlen;
	unsigned char *hash = NULL;
	char *hexa;

	/* get the public key */
	err = ssh_get_publickey(session, &key);
	if(err == SSH_ERROR)
		return BACKUPSSH_PUBKEY_ERR;

	/*  get the hash */
	err = ssh_get_publickey_hash(key, SSH_PUBLICKEY_HASH_SHA1, &hash,
			&hlen);
	if (err == -1)
		return BACKUPSSH_HASH_ERR;
	/*  get the cool hash */
	hexa = ssh_get_hexa(hash, hlen);
	if(hexa == NULL)
		return BACKUPSSH_HASH_ERR;
	/*  leave the actual work to another function */
	return is_host_known(hexa);
}

int is_host_known(char *hash)
{
	/*  open known hosts file */
	FILE *fp = fopen("hosts.kwn", "r");
	if(fp == NULL)
		return BACKUPSSH_HOST_UNKNOWN;

	char buf[4096];
	do {
		fseek(fp, 1, SEEK_CUR);
		fgets(&buf[0], 4096, fp);
		if(strcmp(&buf[0], hash) == 0)
		return BACKUPSSH_HOST_KNOWN;
	} while(fgetc(fp) != EOF);

	return BACKUPSSH_HOST_UNKNOWN;
}
