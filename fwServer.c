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
 * Función que devuelve el resultado de la operación efectuada.
 * @param opcode codigo con el resultado de la operación.
 */
void msg_return(int sock, int opcode){

    char response[sizeof(op_err)];    //La peor respuesta es que sea un ERROR,
                                      //por eso escogemos ese tamaño máximo;
    if(opcode == MSG_OK){
        op_ok msg;
        msg.opcode = MSG_OK;
        stshort(msg.opcode, response);
    }else{
        op_err msg;
        msg.opcode = MSG_ERR;
        msg.error_code = ERR_RULE;
        stshort(msg.opcode, response);
        stshort(msg.error_code, response + sizeof(msg.opcode));
    }

    if (send(sock, response, sizeof(op_err), 0) < 0) {
        perror("ERROR writing to socket");
        exit(1);
    }
}


/**
 * Function that sends a HELLO_RP to the client
 * @param sock the communications socket
 */
void process_HELLO_msg(int sock)
{

    printf("PROCESSING HELLO MSG\n");

    char buffer[MAX_BUFF_SIZE];
    op_hello_rp hello_rp;
    int n;

    stshort(MSG_HELLO_RP,&hello_rp.opcode);
    strcpy(hello_rp.msg,"Hello World\0");

    *((op_hello_rp *)buffer) = hello_rp;

    n = send(sock,buffer,sizeof(hello_rp),0);

    if (n < 0) {
        perror("ERROR writing to socket");
        exit(1);
    }
}



/**
 * Función que envia al cliente una lista con las reglas del firewall.
 * @param sock socket que se utiliza para la comunicación.
 * @param chain la cadena con que contiene las reglas de filtrado.
 */
void process_RULES(int sock, struct FORWARD_chain *chain)
{

    printf("PROCESSING RULES MSG\n");

    char buffer[MAX_BUFF_SIZE];
    char *offset;

    bzero(buffer,MAX_BUFF_SIZE);

    stshort(MSG_RULES,buffer);
    stshort(chain->num_rules,buffer+sizeof(unsigned short));

    struct fw_rule fw_rule_current;
    offset = (buffer + 2*sizeof(unsigned short));

    if(chain->first_rule != NULL){
        int finish = 0;
        fw_rule_current = *chain->first_rule;
        do{
            *((rule *)offset) = fw_rule_current.rule;
            if(fw_rule_current.next_rule != NULL)
                fw_rule_current = *fw_rule_current.next_rule;
            else finish = 1;
            offset += sizeof(rule);
        }while(!finish);
    }

    //Send list
    if (send(sock,buffer,MAX_BUFF_SIZE,0) < 0) {
        perror("ERROR writing to socket");
        exit(1);
    }


}

/**
 * Función que agregra una nueva regla a la lista con las reglas del firewall.
 * @param sock socket que se utiliza para la comunicación.
 * @param chain la cadena con que contiene las reglas de filtrado.
 * @param buffer buffer con la información perteneciente a la nueva regla que se desea agregar a la lista.
 */
void process_ADD(int sock, struct FORWARD_chain *chain, rule buffer)
{

    printf("PROCESSING ADD\n");

    struct fw_rule *new_fw_rule = (struct fw_rule*)malloc(sizeof(struct fw_rule));
    new_fw_rule->rule = buffer;
    new_fw_rule->next_rule = NULL;

    if(chain->first_rule != NULL){
        struct fw_rule *tmp;
        tmp = chain->first_rule;
        while(tmp->next_rule != NULL){
            tmp = tmp->next_rule;
        }
        tmp->next_rule = new_fw_rule;

    }else{
        chain->first_rule = new_fw_rule;
    }

    chain->num_rules += 1;

    msg_return(sock,MSG_OK);
}

/**
 * Función que modifica la regla de firewall escogida de la lista.
 * @param sock socket que se utiliza para la comunicación.
 * @param chain la cadena con que contiene las reglas de filtrado.
 * @param buffer buffer con la información perteneciente a la regla que se desea modificar.
 */
void process_CHANGE(int sock, struct FORWARD_chain *chain, op_change *buffer)
{
    printf("PROCESSING CHANGE\n");

    unsigned short id;
    int count = 1;
    int found = FALSE;
    struct fw_rule *p;

    p = chain->first_rule;
    id = ldshort(&buffer->rule_id);

    while ((p!= NULL) && !found) {

        if (count == id) {
            found = TRUE;
        } else {
            p = p->next_rule;
            count++;
        }
    }

    if (found) {
        p->rule = buffer->rule_change;
        msg_return(sock,MSG_OK);
    }else{
        msg_return(sock,MSG_ERR);
    }

}

/**
 * Función que elimina la regla escogida de la lista con las reglas del firewall.
 * @param sock socket que se utiliza para la comunicación.
 * @param chain la cadena con que contiene las reglas de filtrado.
 * @param buffer buffer con la información perteneciente a la regla que se desea eliminar.
 */
void process_DELETE(int sock, struct FORWARD_chain *chain, op_delete *delete_rule)
{

    printf("PROCESSING DELETE\n");

    int count = 1;
    int found = FALSE;
    int valid = FALSE;
    unsigned short id_h;
    struct fw_rule *p;

    p = chain->first_rule;
    id_h = ldshort(&delete_rule->rule_id);

    if(p != NULL) {

        // HEAD
        if(id_h == 1){

            struct fw_rule *temp_r = p->next_rule;
            free(p);
            chain->first_rule = temp_r;
            valid = TRUE;

        }else {

            while ((p->next_rule != NULL) && !found) {

                if (count == (id_h - 1)) {
                    found = TRUE;
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

    if(valid) {
        msg_return(sock,MSG_OK);
    }else{
        msg_return(sock,MSG_OK);
    }
}

/**
 * Función que elimina todas las reglas de la lista..
 * @param sock socket que se utiliza para la comunicación.
 * @param chain la cadena con que contiene las reglas de filtrado.
 */
void process_FLUSH(int sock, struct FORWARD_chain *chain){

    printf("PROCESSING FLUSH\n");

    int num_rules = chain->num_rules;
    int i;
    struct fw_rule *p;

    for(i = 0 ; i<num_rules ; i++){

        p = chain->first_rule;
        struct fw_rule *temp_r = p->next_rule;
        free(p);
        chain->first_rule = temp_r;
        chain->num_rules -= 1;
    }

    msg_return(sock,MSG_OK);

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

    int finish = FALSE;
    char buffer[MAX_BUFF_SIZE];
    unsigned short op_code;

    bzero(buffer,MAX_BUFF_SIZE);

    if (recv(sock, buffer, MAX_BUFF_SIZE, 0) < 0) {
        perror("ERROR reading from socket");
        exit(1);
    }

    // Reads socket OP CODE
    op_code = ldshort(buffer);

    switch(op_code)
    {
        case MSG_HELLO:
            process_HELLO_msg(sock);
            break;
        case MSG_LIST:
            process_RULES(sock,chain);
            break;
        case MSG_ADD:
            process_ADD(sock,chain,*((rule *)(buffer+sizeof(unsigned short))));
            break;
        case MSG_CHANGE:
            process_CHANGE(sock,chain,(op_change *) buffer);
            break;
        case MSG_DELETE:
            process_DELETE(sock,chain,(op_delete *) buffer);
            break;
        case MSG_FLUSH2:
            process_FLUSH(sock,chain);
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
    int s,s2,pid;

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
        pid = fork();

        if(pid > 0){
            close(s);
            do {
                finish = process_msg(s2, &chain);
            }while(!finish);
            close(s2);
            exit(0);

        }else{

            close(s2);
        }
    }
    return 0;
}
