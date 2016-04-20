/***************************************************************************
 *            fwServer.c
 *
 *  Copyright  2016  mc
 *  <mc@<host>>
 ****************************************************************************/

#include "fwServer.h"

/**
 * Returns the port specified as an application parameter or the default port
 * if no port has been specified.
 * @param argc the number of the application arguments.
 * @param an array with all the application arguments.
 * @return  the port number from the command line or the default port if
 * no port has been specified in the command line. Returns -1 if the application
 * has been called with the wrong parameters.
 */
int getPort(int argc, char* argv[])
{
    int param;
    int port = DEFAULT_PORT;

    optind=1;
    // We process the application execution parameters.
    while((param = getopt(argc, argv, "p:")) != -1){
        switch((char) param){
            case 'p':
                // We modify the port variable just in case a port is passed as a
                // parameter
                port = atoi(optarg);
                break;
            default:
                printf("Parametre %c desconegut\n\n", (char) param);
                port = -1;
        }
    }

    return port;
}


/**
 * Function that sends a HELLO_RP to the client
 * @param sock the communications socket
 */
void process_HELLO_msg(int sock)
{

    printf("PROCESSING HELLO MSG\n");

    char buffer[MAX_BUFF_SIZE];
    struct hello_rp hello_rp;
    int n;

    /*
    stshort(2,hello_rp.opcode);

    memcpy(hello_rp.msg,"Hello World\0",12);


    *((struct hello_rp *)buffer) = hello_rp;
     *

    printf("Send: %hu %s\n",hello_rp.opcode,hello_rp.msg);
     */

    n = send(sock,"asdf",sizeof("asdf"),0);

}

/**
 * Receives and process the request from a client.
 * @param the socket connected to the client.
 * @param chain the chain with the filter rules.
 * @return 1 if the user has exit the client application therefore the
 * connection whith the client has to be closed. 0 if the user is still
 * interacting with the client application.
 */
int process_msg(int sock, struct FORWARD_chain *chain)
{
    unsigned short op_code;
    int finish = 0;
    int n;
    char buffer[MAX_BUFF_SIZE];

    bzero(buffer,MAX_BUFF_SIZE);

    n = recv(sock, buffer, sizeof(buffer), 0);

    if (n < 0) {
        perror("ERROR reading from socket");
        exit(1);
    }
    // Reads socket OP CODE
    op_code = ldshort(buffer);
    printf("OPcode: %hu\n",op_code);

    switch(op_code)
    {
        case MSG_HELLO:

            process_HELLO_msg(sock);
            break;
        case MSG_LIST:
            break;
        case MSG_ADD:
            break;
        case MSG_CHANGE:
            break;
        case MSG_DELETE:
            break;
        case MSG_FLUSH:
            break;
        case MSG_FINISH:
            finish = 1;
            break;
        default:
            perror("Message code does not exist.\n");
    }

    return finish;
}

int main(int argc, char *argv[]){

    int port = getPort(argc, argv);
    int finish=0;
    struct FORWARD_chain chain;

    struct sockaddr_in serv_addr, cli_addr;
    int s,s2;

    chain.num_rules=0;
    chain.first_rule=NULL;



    s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (s < 0) {
        perror("ERROR opening socket");
        exit(1);
    }

    /* Initialize socket structure */

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);

    /* Now bind the host address */
    if (bind(s, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        perror("ERROR on binding");
        exit(1);
    }

    /*Start listening for the clients */

    listen(s,MAX_QUEUED_CON);

    socklen_t client_addrlen = sizeof(cli_addr);


    while(1) {

        /* Accept actual connection from the client */
        s2 = accept(s, (struct sockaddr *)&cli_addr, &client_addrlen);

        if (s2 < 0) {
            perror("ERROR on accept");
            exit(1);
        }

        do {

            finish = process_msg(s2, &chain);

        }while(!finish);


        close(s2);

        return 0;
    }

    close(s);

    return 0;
}
