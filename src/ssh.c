#include <ssh.h>
#include <error.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int create_ssh_session(ssh_session *session, const char *host, int verbosity, int port)
{
	*session = ssh_new();
	if(session == NULL)
		return BACKUPSSH_SESSION_CREATE;
	ssh_options_set(*session, SSH_OPTIONS_HOST, host);
	ssh_options_set(*session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
	ssh_options_set(*session, SSH_OPTIONS_PORT, &port);

	return BACKUPSSH_SUCCESS;
}

int verify_ssh_host(ssh_session session, char **ret_hash)
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

	/* give hash back to callee */
	if(ret_hash)
		*ret_hash = hexa;
	/*  leave the actual work to another function */
	return is_host_known(session, hexa);
}

int is_host_known(ssh_session session, char *hash)
{
	/*  open known hosts file */
	FILE *fp = fopen("hosts.kwn", "r");
	if(fp == NULL) {
		fclose(fp);
		/* assume that if the file doesn't exist the host is unkown */
		return BACKUPSSH_HOST_UNKNOWN;
	}
	char buf[4096];
	do {
		fgets(buf, 4096, fp);
		fseek(fp, 1, SEEK_CUR);
		char *ip, *shash;
		const char delim[2] = ", ";

		/*  remove trailing newline */
		strtok(buf, "\n");
		/*  seperate values */
		ip = strtok(buf, delim);
		shash = strtok(NULL, delim);

		/* get remote host ip */
		char *remote_host;
		if(ssh_options_get(session, SSH_OPTIONS_HOST, &remote_host)
				== SSH_ERROR)
			exit(1);

		/*  now check if they are the same */
		if(strcmp(ip, remote_host) == 0 && strcmp(shash, hash) == 0) {
			fclose(fp);
			return BACKUPSSH_HOST_KNOWN;
		}
		if(strcmp(ip, remote_host) == 0 && strcmp(shash, hash) != 0) {
			fclose(fp);
			return BACKUPSSH_HOST_HASH_CHANGED;
		}
		if(strcmp(ip, remote_host) != 0 && strcmp(shash, hash) == 0) {
			fclose(fp);
			return BACKUPSSH_HOST_IP_CHANGED;
		}
	} while(fgetc(fp) != EOF);

	fclose(fp);
	return BACKUPSSH_HOST_UNKNOWN;
}

int add_host(const char *host, const char *hash)
{
	/* open file for writing */
	FILE *fp = fopen("hosts.kwn", "w");
	if(fp == NULL) {
		fclose(fp);
		return BACKUPSSH_FILE_OPEN_ERR;
	}
	/* write the hosts and hash to the file */
	fseek(fp, 0, SEEK_END);
	fprintf(fp, "%s, %s", host, hash);
	fclose(fp);

	return BACKUPSSH_SUCCESS;
}

int authenticate_ssh_host(ssh_session session, int method,
		const char *password, const char *pub_key_file,
		const char *priv_key_file)
{
	int err;
	switch(method) {
		case KEY: {
			ssh_key pub_key = ssh_key_new();
			err = ssh_pki_import_pubkey_file(pub_key_file,
					&pub_key);
			if(err != SSH_OK) {
				ssh_key_free(pub_key);
				return BACKUPSSH_PUBKEY_ERR;
			}
			err = ssh_userauth_try_publickey(session, "backup",
					pub_key);
			if(err != SSH_AUTH_SUCCESS) {
				ssh_key_free(pub_key);
				return BACKUPSSH_AUTH_ERR;
			}

			ssh_key priv_key = ssh_key_new();
			err = ssh_pki_import_privkey_file(priv_key_file,
					password, NULL, NULL, &priv_key);
			if(err != SSH_OK) {
				ssh_key_free(pub_key);
				ssh_key_free(priv_key);
				return BACKUPSSH_PRIVKEY_ERR;
			}

			err = ssh_userauth_publickey(session, "backup",
					priv_key);
			ssh_key_free(pub_key);
			ssh_key_free(priv_key);
			if(err != SSH_AUTH_SUCCESS)
				return BACKUPSSH_AUTH_ERR;
			return BACKUPSSH_SUCCESS;
		}
		case PASSWORD: {
			err = ssh_userauth_password(session, NULL, password);
			if(err != SSH_AUTH_SUCCESS)
				return BACKUPSSH_AUTH_ERR;
			return BACKUPSSH_SUCCESS;
		}
	}
	return BACKUPSSH_SUCCESS;
}
