#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pwd.h>
#include <netinet/in.h>
#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"
#include "sgx_tcrypto.h"


#define PORT 8080

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }
    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}

int init_socket(){
    /*************************
     * BEGIN 1. Communication A_A, A_B; Socket Setup and Test
     *************************/
    //Based on https://www.geeksforgeeks.org/socket-programming-cc/

    int server_fd, new_socket, valread, valsend;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};
    char *hello = "Hello from server";
       
    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
       
    // Forcefully attaching socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                                                  &opt, sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons( PORT );
       
    // Forcefully attaching socket to the port 8080
    if (bind(server_fd, (struct sockaddr *)&address, 
                                 sizeof(address))<0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, 
                       (socklen_t*)&addrlen))<0)
    {
        perror("accept");
        exit(EXIT_FAILURE);
    }
    
    valread = read(new_socket , buffer, 1024);
    if(valread < 0){
        printf("Error while reading data from socket");
    }
    printf("%s\n",buffer );
    valsend = send(new_socket , hello , strlen(hello) , 0 );
    if (valsend < 0){
        printf("Error while sending data to socket.");
    }
    printf("Hello message sent\n");

    return new_socket;
    /*************************
     * END 1. Communication A_A, A_B; Socket Setup and Test
     *************************/
}

int compute_shared_key(int socket){
    sgx_status_t sgx_status;
    int valread, valsend;

    /* Initialize Key Pair */
    sgx_ec256_public_t public_key_B;
    createKeyPair(global_eid, &sgx_status, &public_key_B);
    if (sgx_status != SGX_SUCCESS) {
        print_error_message(sgx_status);
        return -1;
    }
    printf("From App: Create Key Pair Success. \n");


    /*************************
     * BEGIN 1. Communication A_A, A_B; Receive public key from A
     *************************/
    sgx_ec256_public_t public_key_A;

    unsigned char public_key_A_x[32];
    valread = read(socket , public_key_A_x, 32);
    if(valread < 0){
        printf("Error while reading data from socket");
        return -1;
    }
    memcpy(public_key_A.gx, public_key_A_x, 32);


    unsigned char public_key_A_y[32];
    valread = read(socket , public_key_A_y, 32);
    if(valread < 0){
        printf("Error while reading data from socket");
        return -1;
    }
    memcpy(public_key_A.gy, public_key_A_y, 32);
    /*************************
     * END 1. Communication A_A, A_B; Receive public key from A
     *************************/



    /*************************
     * BEGIN 1. Communication A_A, A_B; Send public key to A
     *************************/
    unsigned char public_key_B_x[32];
    memcpy(public_key_B_x, public_key_B.gx, 32);
    valsend = send(socket, public_key_B_x, 32, 0);
    if (valsend < 0){
        printf("Error while sending data to socket.");
        return -1;
    }

    unsigned char public_key_B_y[32];
    memcpy(public_key_B_y, public_key_B.gy, 32);
    valsend = send(socket, public_key_B_y, 32, 0);
    if (valsend < 0){
        printf("Error while sending data to socket.");
        return -1;
    }
    /*************************
     * END 1. Communication A_A, A_B; Send public key to A
     *************************/

    computeSharedKey(global_eid, &sgx_status, &public_key_A);
    if (sgx_status != SGX_SUCCESS) {
        print_error_message(sgx_status);
        return -1;
    }
    return 1;
}

int exchange_psk(int socket){
    sgx_status_t sgx_status;

     /*************************
     * BEGIN 1. Communication A_A, A_B; Receive PSK from A
     *************************/
    unsigned char psk_A[16] = {0};
    if(read(socket , psk_A, 16) < 0){
        printf("Error while reading data from socket");
        return -1;
    }
    /*************************
     * END 1. Communication A_A, A_B; Receive PSK from A
     *************************/

    int correct_psk = 0;
    sgx_status = readPSK(global_eid, &sgx_status, psk_A, &correct_psk);
    if (sgx_status != SGX_SUCCESS) {
        print_error_message(sgx_status);
        return -1;
    }
    if (!correct_psk){
        printf("Wrong PSK from A.\n");
        return -1;
    }
    printf("Correct PSK from A.\n");

    //Send PSK to B
    unsigned char message[16] = {0};
    sgx_status = getPSK(global_eid, &sgx_status, message);
    if (sgx_status != SGX_SUCCESS) {
        print_error_message(sgx_status);
        return -1;
    }

    /*************************
     * BEGIN 1. Communication A_A, A_B; Send PSK to A
     *************************/
    if (send(socket, message, 16, 0) < 0){
        printf("Error while sending data to socket.");
        return -1;
    }
    /*************************
     * END 1. Communication A_A, A_B; Send PSK to A
     *************************/


    /*************************
     * BEGIN 1. Communication A_A, A_B; Confirm PSK exchange
     *************************/
    const char psk_ok_string[16] = "PSK exchange ok";
    unsigned char message_psk_ok[16] = {0};
    if(read(socket, message_psk_ok, 16) < 0){
        printf("Error while reading data from socket");
        return -1;
    }
     /*************************
     * END 1. Communication A_A, A_B; Confirm PSK exchange
     *************************/
    if (strcmp((const char *) message_psk_ok, psk_ok_string) != 0){
        printf("PSK Exchange not complete.\n" );
        return -1;
    }
    return 1;
}


int complete_challenge(int socket){
    sgx_status_t sgx_status;

     /*************************
     * BEGIN 1. Communication A_A, A_B; Get challenge from A
     *************************/
    unsigned char message[8] = {0};
    if(read(socket , message, 8) < 0){
        printf("Error while reading data from socket");
        return -1;
    }
     /*************************
     * END 1. Communication A_A, A_B; Get challenge from A
     *************************/

    //Complete Challenge
    unsigned char result[4] = {0};
    completeChallenge(global_eid, &sgx_status, message, result);
    if (sgx_status != SGX_SUCCESS) {
        print_error_message(sgx_status);
        return -1;
    }

    /*************************
     * BEGIN 1. Communication A_A, A_B; Send challenge results to A
     *************************/
    if (send(socket, result, 4, 0) < 0){
        printf("Error while sending data to socket.");
        return -1;
    }
    /*************************
     * END 1. Communication A_A, A_B; Send challenge results to A
     *************************/

    
    /*************************
     * BEGIN Communication A_A, A_B; Confirm challenge
     *************************/
    unsigned char challenge_complete[16] = {0};
    if(read(socket, challenge_complete, 16) < 0){
        printf("Error while reading data from socket");
        return -1;
    }
    /*************************
     * END Communication A_A, A_B; Confirm challenge
     *************************/

    const char challenge_string[16] = "Challenge done!";
    if (strcmp((const char *) challenge_complete, challenge_string) != 0){
        printf("Challenge not complete.\n" );
        return -1;
    }
    return 1;
}
/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);
    sgx_status_t sgx_status;

    /* Initialize Socket */
    int socket = init_socket();
     
    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enclave initialization failed.\n");
        return -1;
    }
    printf("From App: Enclave creation success. \n");
    
    /* Compute shared key */
    if (compute_shared_key(socket) < 0){
        printf("Error while computing shared key. \n");
        return -1;
    }
    printf("From App: Compute Shared Key Success. \n");

    /* Exchange PSK */
    if (exchange_psk(socket) < 0){
        printf("Error while exchannging PSK. \n");
        return -1;
    }
    printf("From App: Exchange PSK Success. \n");


    /* Complete challenge 20 times */
    for (int i = 0; i < 20; i++){
        if (complete_challenge(socket) < 0){
            printf("Error while completing challenge. \n");
            return -1;
        }
        printf("Challenge %u Sucecss. \n", i);
    }
    printf("Completed all challenges successfully.\n");
    


    printSecret(global_eid, &sgx_status);
    if (sgx_status != SGX_SUCCESS) {
        print_error_message(sgx_status);
        return -1;
    }

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

    printf("From App: Enclave destroyed.\n");
    return 0;
}

