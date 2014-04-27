//
// compiled with arm-unknown-linux-gnueabi-gcc Whitelist-CGI.c -o Whitelist-CGI.cgi
//
#define sizearray(a)  (sizeof(a) / sizeof((a)[0]))

#include "stdio.h"
#include "unistd.h"
#include "stdlib.h"
#include "string.h"


#define QS_LEN 65536


int main(void) {

  //Initialise variables for whitelist call
  char *var_d;
  char *var_b;
  char *var_t;
  char *var_s;

  char *data;
  char *token;
  char *key;
  char *value;


  //Allocate memory to variables
  data = malloc(QS_LEN);
  token = malloc(QS_LEN);
  key = malloc(QS_LEN);
  value = malloc(QS_LEN);


  var_d = malloc(QS_LEN);
  var_b = malloc(QS_LEN);
  var_t = malloc(QS_LEN);
  var_s = malloc(QS_LEN);

  //Query request string and allocate values received to variables
  if (getenv("QUERY_STRING"))
  {
   token = strtok (getenv("QUERY_STRING"),"&");
   while (token != NULL)
   {
	sscanf(token, "%[^=]=%65536s", key, value);
	if ( compStr(key, "d", sizearray(key) ))
	{
		strcpy(var_d, value);
	}
	if ( compStr(key, "b", sizearray(key) ))
	{
		strcpy(var_b, value);
	}
	if ( compStr(key, "t", sizearray(key) ))
	{
		strcpy(var_t, value);
	}
	if ( compStr(key, "s", sizearray(key) ))
	{
		strcpy(var_s, value);
	}
	token = strtok (NULL, "&");
   }
  }

  FILE *fp;
  mkdir("/data/eureka", 0777);
  char path[1035];

  //Check if Whitelist bypass to Google is enabled
  fp = popen("EurekaSettings get WhiteList useSelection", "r");
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
		//If all device variables provided pass onto google
		if ((strlen(var_b) != 0) && (strlen(var_s) != 0) && (strlen(var_d) != 0) && (strlen(var_t) != 0))
		{
		 printf( "Location: http://clients3.google.com/cast/chromecast/device/baseconfig?b=%s&d=%s&t=%s&s=%s\n\n\n", var_b, var_d, var_t, var_s);
		}
		else{
		//Not all device variables provided, check for device version config and pass to google
		  if(strlen(var_b) != 0){
  			printf( "Location: http://clients3.google.com/cast/chromecast/device/baseconfig?b=%s\n\n\n", var_b);
  		  }
		  else{
			//device config version not provided, proceed to google emulating 14651
  			printf( "Location: http://clients3.google.com/cast/chromecast/device/baseconfig?b=14651\n\n\n" );
		  }
		}
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

  //Read whitelist from file, print to web.
  FILE *ptr_file;
  char buf[1000];

  //If web is up, force update check
  ptr_file = popen("ping -c 1 -w 1 google.com > /dev/null ; echo $?", "r");
  while (fgets(path, sizeof(path)-1, ptr_file) != NULL) {
	if (compStr(path, "0\n", sizearray(path) )) { 
		system( "busybox sh /system/usr/share/eureka-apps/whitelist-sync/whitelist-sync > /tmp/whitelist-sync.log" );
	}
   }

  //check if whitelist apps.conf exists in data (if not use system apps.conf)
  if(access("/data/eureka/apps.conf", F_OK) != -1 ) {
      ptr_file =fopen("/data/eureka/apps.conf","r");
  }  else {
	ptr_file=fopen("/system/usr/share/eureka-apps/configs/apps.conf", "r");
  }

  while (fgets(buf,1000, ptr_file)!=NULL)
      printf("%s",buf);
      fclose(ptr_file);

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
