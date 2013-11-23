//
// compiled with arm-unknown-linux-gnueabi-gcc Whitelist-CGI.c -o Whitelist-CGI.cgi
//

#include "stdio.h"
#include "unistd.h"

int main(void) {
  //Check for directory structure in Data (note using mkdir over stat checks for speed considerations)
  mkdir("/data/www/whitelist", 0777);
  mkdir("/data/www/cgi-bin", 0777);

  //Print required header information
  //Note: Date is currently static however no impact on CC
  printf( "HTTP/1.1 200 OK\n" );
  printf( "Content-Type: application/json; charset=utf-8\n" );
  printf( "Cache-Control: no-cache, no-store, max-age=0, must-revalidate\n" );
  printf( "Pragma: no-cache\n" );
  printf( "Expires: Fri, 01 Jan 1990 00:00:00 GMT\n" );
  printf( "Date: Sat, 23 Nov 2013 01:15:47 GMT\n" );
  printf( "Content-Disposition: attachment; filename=\"json.txt\"; filename*=UTF-8''json.txt\n" );
  printf( "X-Content-Type-Options: nosniff\n" );
  printf( "X-Frame-Options: SAMEORIGIN\n" );
  printf( "X-XSS-Protection: 1; mode=block\n" );
  printf( "Server: GSE\n" );
  printf( "Alternate-Protocol: 443:quic\n" );
  printf( "Transfer-Encoding: chunked\n\n" );

  //Add configuration detail to whitelist
  printf( ")]}'\n{\"configuration\":{\"idle_screen_app\":\"00000000-0000-0000-0000-000000000000\"},\"applications\":\n" );

  //Read whitelist from file, print to web.
  FILE *ptr_file;
  char buf[1000];

  //check if whitelist apps.conf exists in data (if not use system apps.conf)
  if(access("/data/www/whitelist/apps.conf", F_OK) != -1 ) {
      ptr_file =fopen("/data/www/whitelist/apps.conf","r");
  }  else {
      ptr_file=fopen("/system/etc/apps.conf", "r");
  }

  while (fgets(buf,1000, ptr_file)!=NULL)
      printf("%s",buf);
  fclose(ptr_file);

  //Close whitelist configuration
  printf( "}" );

  //Return successfully.
  return 0;
}
