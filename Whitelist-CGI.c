//
// compiled with arm-unknown-linux-gnueabi-gcc Whitelist-CGI.c -o Whitelist-CGI.cgi
//

#include "stdio.h"
#include "unistd.h"

int main(void) {
  FILE *fp;
  mkdir("/data/eureka", 0777);
  char path[1035];

  //Check if Whitelist bypass to Google is enabled
  fp = popen("EurekaSettings get WhiteList useGoogle", "r");
  //error out if command fails
  if (fp == NULL) {
  printf("Failed to run command\n" );
  return 0;
  }
  //compare value of EurekaSettings
  while (fgets(path, sizeof(path)-1, fp) != NULL) {
  	if(compStr(path, "1")){
		//Bypass enabled, redirect to Google
  		printf( "HTTP/1.1 302 Object moved\n" );
  		printf( "Location: http://clients3.google.com/cast/chromecast/device/baseconfig?b=14651\n\n\n" );
	} else {

  //Redirect not present, present local whitelist
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
  printf( ")]}'\n{\"configuration\":{\"idle_screen_app\":\"00000000-0000-0000-0000-000000000000\"}, \"enabled_app_ids\":[\"087FCD5C\",\"2EEAFD9A\",\"30F4C306\",\"514E28B7\",\"552553BC\",\"674A0243\",\"6EBBD6E0\",\"85F0B427\",\"B88E20BD\",\"BFEBD3F1\",\"C27C2913\",\"C8939A18\",\"CC1AD845\",\"D6045317\",\"D8D09EE8\",\"E1F15514\",\"E9250490\",\"E93E3FCD\",\"EA126165\",\"ECE66B88\",\"FEE7AE75\"],\"applications\":\n" );

  //Read whitelist from file, print to web.
  FILE *ptr_file;
  char buf[1000];

  //check if whitelist apps.conf exists in data (if not use system apps.conf)
  if(access("/data/eureka/apps.conf", F_OK) != -1 ) {
      ptr_file =fopen("/data/eureka/apps.conf","r");
  }  else {
      ptr_file=fopen("/system/usr/share/eureka-apps/configs/apps.conf", "r");
  }

  while (fgets(buf,1000, ptr_file)!=NULL)
      printf("%s",buf);
  fclose(ptr_file);

  //Close whitelist configuration
  printf( "}" );

	}

  }
  pclose(fp);
  return 0;

}

//Function to compare 2 character arrays for string comparison
int compStr (const char *s1, char *s2, size_t sz) {
    while (sz != 0) {
        // At end of both strings, equal.
        if ((*s1 == '\0') && (*s2 == '\0')) break;

        // Treat spaces at end and end-string the same.
        if ((*s1 == '\0') && (*s2 == ' ')) { s2++; sz--; continue; }
        if ((*s1 == ' ') && (*s2 == '\0')) { s1++; sz--; continue; }

        // Detect difference otherwise.
        if (*s1 != *s2) return 0;
        s1++; s2++; sz--;
    }
    return 1;
}
