#ifndef BACKUPSSH_SSH_H
#define BACKUPSSH_SSH_H

#include <libssh/libssh.h>
#include <error.h>

typedef enum {
	PASSWORD = 0,
	KEY = 1,
} ssh_auth_methods;

/* creates an ssh session from the arguments */
int create_ssh_session(ssh_session *session, const char *host, int verbosity, int port);

/* verifies if the ssh host is known */
int verify_ssh_host(ssh_session session, char **ret_hash);

/* checks if the host is known to us */
int is_host_known(ssh_session session, char *hash);

/* adds host to known hosts list */
int add_host(const char *host, const char *hash);

/* authenticates the host with the given method */
int authenticate_ssh_host(ssh_session session, int method,
		const char *password, const char *pub_key_file,
		const char *priv_key_file);

/* starts the rsync signature retrieval process */
int start_rsync_sig(ssh_session session, const char* dir);

#endif
