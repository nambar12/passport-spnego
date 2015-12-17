#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <gssapi/gssapi.h>
#include "gss-misc.h"
#include "base64.h"


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
      printf("accept_sec_context token (size=%d):\n", result_tok.length);
      print_token(&result_tok);

      (void) gss_release_buffer(&min_stat, &result_tok);
  }
  if (maj_stat!=GSS_S_COMPLETE && maj_stat!=GSS_S_CONTINUE_NEEDED) {
      display_status("accepting context", maj_stat, acc_sec_min_stat);
      if (*context == GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&min_stat, context, GSS_C_NO_BUFFER);
      return -1;
  }
  
  maj_stat = gss_display_name (&min_stat, client, &client_name, NULL);
  if (maj_stat!=GSS_S_COMPLETE)
    printf("ERROR CLIENT\n");
  
  printf("client name is: %.*s.\n", (int) client_name.length, (char *) client_name.value);
  /*print_token(&client_name);*/

  if (maj_stat == GSS_S_CONTINUE_NEEDED)
      fprintf(stderr, "continue needed...\n");
  else
      fprintf(stderr, "\n");

}


int main(int argc, char **argv) {

  if(argc != 2) {
    fprintf(stderr, "Usage: %s <token>\n", argv[0]);
    exit -1;
  }
  
  const char *base64token = argv[1];
  
  gss_buffer_desc token;
  token.value = base64_decode(base64token, strlen(base64token), &token.length);
  printf("decoded token size is %i\n",token.length);
  
  gss_cred_id_t server_creds;
  display_file = stdout;

  char *service_name = "HTTP\\/itstl220.iil.intel.com\\@GER.CORP.INTEL.COM";

  if (acquire_creds(service_name, &server_creds) < 0)
    return -1;

  gss_ctx_id_t context;
  int ret_flags;
  if (check_token(&token, server_creds, &context, &ret_flags) < 0)
    return -1;
}
