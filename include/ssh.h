#ifndef BACKUPSSH_SSH_H
#define BACKUPSSH_SSH_H

#include <libssh/libssh.h>

/* creates an ssh session from the arguments */
ssh_session create_ssh_session(const char *host, int verbosity, int port);

/* verifies if the ssh host is known */
int verify_ssh_host(ssh_session session);

/* authenticates the host with the given method */
int authenticate_ssh_host(ssh_session session, int method,
	       	const char *password, const char *key_file);

/* starts the rsync signature retrieval process */
int start_rsync_sig(ssh_session session, const char* dir);

#endif
