/********
Client-side program of short message communication using pthreads
Date: 07 Nov 2020
********/

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<pthread.h>
#include<sys/time.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/in.h>

// Constants
#define SERVER_ADDRESS "192.168.56.101"
#define BUFFER_SIZE 65536
#define MAX_NUM_PORTS 10

// Function pointer argument data type
typedef struct {
	int sock;
	int port;
} sock_data;

void *receive_messages(void *);

int main()
{
	// Variables
	int i, num_port;
	int sock[MAX_NUM_PORTS], port[MAX_NUM_PORTS];
	char server_addr[16] = SERVER_ADDRESS;
	struct sockaddr_in sock_addr;
	pthread_t pthread[MAX_NUM_PORTS];
	void *error_code[MAX_NUM_PORTS];

	// Constants
	const int sock_addr_len = sizeof(struct sockaddr_in);

	while(1) {
		// Get number of ports
		printf("Enter {(number of ports) (port 1) (port 2) ...}: ");
		scanf("%d", &num_port);

		// Make connections
		for (i = 0; i < num_port; i++) {
			// Get a port number
			scanf("%d", &port[i]);

			// Make a socket
			if ((sock[i] = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
				printf("Socket Creation Failure: Port #%d (%d)\n", i + 1, port[i]);
				return 0;
			}

			// Configurate that socket
			memset(&sock_addr, 0, sock_addr_len);
			sock_addr.sin_family = AF_INET;
			sock_addr.sin_port = htons(port[i]);
			sock_addr.sin_addr.s_addr = inet_addr(server_addr);

			// Connect to the server with that socket
			if (connect(sock[i], (struct sockaddr *)&sock_addr, sock_addr_len) < 0) {
				printf("Socket Connection Failure: Port #%d (%d)\n", i + 1, port[i]);
				return 0;
			}
		}

		// Make pthreads
		printf("open: ");
		for (i = 0; i < num_port; i++) {
			// Prepare arguments
			sock_data *pt_data = (sock_data *)malloc(sizeof(sock_data));
			pt_data->sock = sock[i];
			pt_data->port = port[i];

			// Create pthreads
			if (pthread_create(&pthread[i], NULL, receive_messages, (void *)pt_data) < 0) {
				printf("PThread Generation Failure: Port #%d (%d)\n", i + 1, port[i]);
				return 0;
			}

			// Join pthreads
			if (pthread_join(pthread[i], &error_code[i]) < 0) {
				printf("PThread Join Failure: Port #%d (%d)\n", i + 1, port[i]);
				return 0;
			}

			printf("%d ", port[i]);
		}
		printf("\n");	

		// Detect error
		for (i = 0; i < num_port; i++) {
			if ((long)error_code[i] != 0) {
				printf("PThread Function Failure: Port #%d (%d) - CODE %ld\n", i + 1, port[i], (long)error_code[i]);
			}
		}

		printf("close\n");
	}

	return 0;
}
void *receive_messages(void *data)
{
	// Variables
	FILE *fp;
	struct tm *lt;
	struct timeval tv;
	int sock = ((sock_data *)data)->sock;
	int port = ((sock_data *)data)->port;
	char file_name[50];
	char buffer[BUFFER_SIZE] = {0};

	// Generate file name as "{PORT}.txt"
	sprintf(file_name, "./%d-%d.txt", port, sock);

	// Open a file
	fp = fopen(file_name, "at");

	while(1) {
		// Start reading
		read(sock, buffer, BUFFER_SIZE);

		// When receive a message, record current time
		if (gettimeofday(&tv, NULL) < 0) {
			fclose(fp);
			close(sock);
			return (void *)1;
		}

		// Change time storing format
		if ((lt = localtime(&tv.tv_sec)) == NULL) {
			fclose(fp);
			close(sock);
			return (void *)2;
		}

		// Append message to the file
		fprintf(fp, "%02d:%02d:%02d.%03ld|%ld|%s\n",
			lt->tm_hour, lt->tm_min, lt->tm_sec, tv.tv_usec,
			strlen(buffer), buffer);

		// Stop communication when receive "@@@@@"
		if (strstr(buffer, "@@@@@") != NULL) {
			fclose(fp);
			close(sock);
			break;
		}
	}

	return (void *)0;
}
