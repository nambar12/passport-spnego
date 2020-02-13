#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <gssapi/gssapi.h>
#include <getopt.h>
#include "gss-misc.h"
#include "base64.h"


/* global options */
static int verbose;
static char* spn;
static char* keytab;
static char* client_token;

static struct option long_options[] = {
    {"verbose", no_argument,       &verbose, 1  },
    {"spn",     required_argument, 0,        's'},
    {"keytab",  required_argument, 0,        'k'},
    {"token",   required_argument, 0,        't'},
    {0, 0, 0, 0}
};

void get_options(int argc, char** argv) {
    int c;
	int option_index = 0;
    while(1) {
	  c = getopt_long (argc, argv, "s:t:", long_options, &option_index);
	  if (c == -1)
        break;
	  
	  switch(c) {
		case 0:
		  if (long_options[option_index].flag != 0)
			  break;
		case 's':
		  spn = optarg;
			break;
		case 'k':
		  keytab = optarg;
			break;
		case 't':
		  client_token = optarg;
			break;
		case '?':
		  break;

		default:
          abort ();
	  }
	}

	if(!spn) {
	  fprintf(stderr,"spn was not specified\n");
	  exit(1);
	}
	if(!client_token) {
	  fprintf(stderr,"token was not specified\n");
	  exit(1);
	}
	if(!keytab) {
	  fprintf(stderr,"keytab was not specified\n");
	  exit(1);
	}
}

int acquire_creds(service_name, server_creds)
     char *service_name;
     gss_cred_id_t *server_creds;
{
     gss_buffer_desc name_buf;
     gss_name_t server_name;
     OM_uint32 maj_stat, min_stat;

     name_buf.value = service_name;
     name_buf.length = strlen(name_buf.value) + 1;
     maj_stat = gss_import_name(&min_stat, &name_buf, 
         (gss_OID) GSS_C_NT_HOSTBASED_SERVICE, &server_name);
     if (maj_stat != GSS_S_COMPLETE) {
         display_status("importing name", maj_stat, min_stat);
         return -1;
     }

     maj_stat = gss_acquire_cred(&min_stat, server_name, 0,
                                 GSS_C_NULL_OID_SET, GSS_C_ACCEPT,
                                 server_creds, NULL, NULL);
     if (maj_stat != GSS_S_COMPLETE) {
          display_status("acquiring credentials", maj_stat, min_stat);
          return -1;
     }


     (void) gss_release_name(&min_stat, &server_name);

     return 0;
}

int check_token(gss_buffer_t token, gss_cred_id_t server_creds, gss_ctx_id_t *context, OM_uint32 *ret_flags) {

  OM_uint32 maj_stat, min_stat, acc_sec_min_stat;
  gss_buffer_desc result_tok;
  gss_buffer_desc client_name;
  gss_name_t client;
  gss_OID doid;

  maj_stat = gss_accept_sec_context(&acc_sec_min_stat,
			      context,
			      server_creds,
			      token,
			      GSS_C_NO_CHANNEL_BINDINGS,
			      &client,
			      &doid,
			      &result_tok,
			      ret_flags,
			      NULL,     /* ignore time_rec */
			      NULL);    /* ignore del_cred_handle */

  (void) gss_release_buffer(&min_stat, token);

  if (result_tok.length != 0) {
	if(verbose) {
      printf("accept_sec_context token (size=%d):\n", result_tok.length);
      print_token(&result_tok);
	}
    (void) gss_release_buffer(&min_stat, &result_tok);
  }
  if (maj_stat!=GSS_S_COMPLETE && maj_stat!=GSS_S_CONTINUE_NEEDED) {
      display_status("accepting context", maj_stat, acc_sec_min_stat);
      if (*context == GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&min_stat, context, GSS_C_NO_BUFFER);
      return -1;
  }
  
  maj_stat = gss_display_name (&min_stat, client, &client_name, NULL);
  if (maj_stat != GSS_S_COMPLETE)
    fprintf(stderr, "ERROR CLIENT\n");
  
  printf("%.*s.\n", (int) client_name.length, (char *) client_name.value);
  return 0;

  /*if (maj_stat == GSS_S_CONTINUE_NEEDED)
      fprintf(stderr, "continue needed...\n");*/
}


int main(int argc, char **argv) {

  get_options(argc, argv);
  setenv("KRB5_KTNAME", keytab, 1);
  
  const char *base64token = argv[1];
  
  gss_buffer_desc token;
  token.value = base64_decode(client_token, strlen(client_token), &token.length);
  if(verbose) {
	fprintf(stderr, "decoded token size is %i\n",token.length);
  }
  
  gss_cred_id_t server_creds;
  display_file = stdout;

  if (acquire_creds(spn, &server_creds) < 0)
    return -1;

  gss_ctx_id_t context = GSS_C_NO_CONTEXT;
  int ret_flags;
  if (check_token(&token, server_creds, &context, &ret_flags) < 0)
    return -1;
  exit(0);
}
