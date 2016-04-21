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

    stshort(MSG_HELLO_RP,&hello_rp.opcode);

    //hello_rp.opcode = htons(2);

    memcpy(hello_rp.msg,"Hello World\0",12);

    *((struct hello_rp *)buffer) = hello_rp;

    printf("Send: %hu %s\n",hello_rp.opcode,hello_rp.msg);


    n = send(sock,buffer,sizeof(hello_rp),0);

    if (n < 0) {
        perror("ERROR writing to socket");
        exit(1);
    }
}



/**
 * Function that sends a List of the rules to the client
 * @param sock the communications socket
 * @param chain of rules
 */
void process_RULES(int sock, struct FORWARD_chain *chain)
{

    char buffer[MAX_BUFF_SIZE];
    unsigned short num_rules;
    char *p;
    int n;

    p = buffer;

    printf("PROCESSING RULES MSG\n");

    stshort(MSG_RULES,buffer);
    p = p+sizeof(unsigned short);

    num_rules = (unsigned short)chain->num_rules;

    memcpy(p,&num_rules,sizeof(unsigned short));
    p = p+sizeof(unsigned short);


    struct fw_rule *offset = chain->first_rule;

    while((offset) != NULL){

        memcpy(p,&offset->rule,sizeof(rule));
        p = p+sizeof(rule);
        offset = offset->next_rule;
        printf("Rule");

    };

    //Send list
    n = send(sock,buffer,MAX_BUFF_SIZE,0);

    if (n < 0) {
        perror("ERROR writing to socket");
        exit(1);
    }


}

void process_ADD(int sock, struct FORWARD_chain *chain, char *buffer)
{

    printf("PROCESSING ADD\n");

    struct fw_rule *new_fw_rule = (struct fw_rule*)malloc(sizeof(struct fw_rule));
    new_fw_rule->rule = *((rule *)buffer);

    if(chain->first_rule == NULL){

        chain->first_rule = new_fw_rule;
        new_fw_rule->next_rule = NULL;
    }else{
        new_fw_rule->next_rule = chain->first_rule;
        chain->first_rule = new_fw_rule;
    }
    chain->num_rules += 1;

    char response[4];
    stshort(MSG_OK,response);

    if (send(sock,response,4,0) < 0) {
        perror("ERROR writing to socket");
        exit(1);
    }

}

void process_CHANGE(int sock, struct FORWARD_chain *chain, char *buffer)
{

    printf("PROCESSING CHANGE\n");

    unsigned short id;

    id = *buffer;
    buffer += sizeof(unsigned short);

    //struct rule *new_fw_rule = (rule*)malloc(sizeof(rule));
    rule changed_rule = *((rule *)buffer);

    int count = 1;
    int found = 0;
    int valid = FALSE;
    struct fw_rule *p;
    p = chain->first_rule;
    while ((p!= NULL) && !found) {

        if (count == id) {
            found = 1;
        } else {
            p = p->next_rule;
            count++;
        }

    }

    if (found) {
        //struct fw_rule *temp_r = p->next_rule;
        p->rule = changed_rule;

        valid = TRUE;

    }

    char response[4];

    if(valid) {
        stshort(MSG_OK, response);

        if (send(sock, response, 2, 0) < 0) {
            perror("ERROR writing to socket");
            exit(1);
        }
    }else{
        stshort(MSG_ERR,response);
        *(response+2) = ERR_RULE;

        if (send(sock,response,4,0) < 0) {
            perror("ERROR writing to socket");
            exit(1);
        }
    }
}

void process_DELETE(int sock, struct FORWARD_chain *chain, unsigned short id)
{

    printf("PROCESSING DELETE\n");

    int count = 1;
    int found = 0;
    int valid = FALSE;
    struct fw_rule *p;
    p = chain->first_rule;
    if(p != NULL) {

        // HEAD
        if(id == 1){

            struct fw_rule *temp_r = p->next_rule;
            free(p);
            chain->first_rule = temp_r;
            valid = TRUE;

        }else {

            while ((p->next_rule != NULL) && !found) {

                if (count == (id - 1)) {
                    found = 1;
                } else {
                    p = p->next_rule;
                    count++;
                }

            }

            if (found) {

                struct fw_rule *temp_r = p->next_rule->next_rule;
                free(p->next_rule);
                p->next_rule = temp_r;

                valid = TRUE;

            }
        }

        chain->num_rules -= 1;

    }

    char response[4];

    if(valid) {
        stshort(MSG_OK, response);

        if (send(sock, response, 2, 0) < 0) {
            perror("ERROR writing to socket");
            exit(1);
        }
    }else{
        stshort(MSG_ERR,response);
        *(response+2) = ERR_RULE;

        if (send(sock,response,4,0) < 0) {
            perror("ERROR writing to socket");
            exit(1);
        }
    }
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
    int finish = FALSE;
    int n;
    char buffer[MAX_BUFF_SIZE];
    char buffer_n_op[MAX_BUFF_SIZE-2];
    unsigned short id;

    bzero(buffer,MAX_BUFF_SIZE);

    n = recv(sock, buffer, MAX_BUFF_SIZE, 0);

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
            process_RULES(sock,chain);
            break;
        case MSG_ADD:
            memcpy(buffer_n_op,buffer+2,12);
            process_ADD(sock,chain,buffer_n_op);
            break;
        case MSG_CHANGE:
            memcpy(buffer_n_op,buffer+2,14);
            process_CHANGE(sock,chain,buffer_n_op);
            break;
        case MSG_DELETE:
            id = (unsigned short) *(buffer+2);
            process_DELETE(sock,chain,id);
            break;
        case MSG_FLUSH:
            break;
        case MSG_FINISH:
            finish = TRUE;
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
