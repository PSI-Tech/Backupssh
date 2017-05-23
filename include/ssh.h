#ifndef BACKUPSSH_SSH_H
#define BACKUPSSH_SSH_H

#include <libssh/libssh.h>
#include <error.h>

/* creates an ssh session from the arguments */
ssh_session create_ssh_session(ssh_error *error, const char *host, int verbosity, int port);

/* verifies if the ssh host is known */
ssh_error verify_ssh_host(ssh_session session);

/* authenticates the host with the given method */
ssh_error authenticate_ssh_host(ssh_session session, int method,
	       	const char *password, const char *key_file);

/* starts the rsync signature retrieval process */
ssh_error start_rsync_sig(ssh_session session, const char* dir);

#endif
