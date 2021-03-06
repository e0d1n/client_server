/***************************************************************************
 *            fwClient.h
 *
 *  Copyright  2016  mc
 *  <mcarmen@<host>>
 ****************************************************************************/
#include "fwClient.h"

/**
 * Function that sets the field addr->sin_addr.s_addr from a host name
 * address.
 * @param addr struct where to set the address.
 * @param host the host name to be converted
 * @return -1 if there has been a problem during the conversion process.
 */
int setaddrbyname(struct sockaddr_in *addr, char *host)
{
    struct addrinfo hints, *res;
    int status;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if ((status = getaddrinfo(host, NULL, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return -1;
    }

    addr->sin_addr.s_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;

    freeaddrinfo(res);

    return 0;
}


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
    while((param = getopt(argc, argv, "h:p:")) != -1){
        switch((char) param){
            case 'h': break;
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
 * Returns the host name where the server is running.
 * @param argc the number of the application arguments.
 * @param an array with all the application arguments.
 * @Return Returns the host name where the server is running.<br />
 * Returns null if the application has been called with the wrong parameters.
 */
char * getHost(int argc, char* argv[]){
    char * hostName = NULL;
    int param;

    optind=1;
    // We process the application execution parameters.
    while((param = getopt(argc, argv, "h:p:")) != -1){
        switch((char) param){
            case 'p': break;
            case 'h':
                      hostName = (char*) malloc(sizeof(char)*strlen(optarg)+1);
                      // Un cop creat l'espai, podem copiar la cadena
                      strcpy(hostName, optarg);
                      break;
            default:
                      printf("Parametre %c desconegut\n\n", (char) param);
                      hostName = NULL;
        }
    }

    printf("in getHost host: %s\n", hostName);
    return hostName;
}



/**
 * Shows the menu options.
 */
void print_menu()
{
    // Mostrem un menu perque l'usuari pugui triar quina opcio fer

    printf("\nAplicació de gestió del firewall\n");
    printf("  0. Hello\n");
    printf("  1. Llistar les regles filtrat\n");
    printf("  2. Afegir una regla de filtrat\n");
    printf("  3. Modificar una regla de filtrat\n");
    printf("  4. Eliminar una regla de filtrat\n");
    printf("  5. Eliminar totes les regles de filtrat.\n");
    printf("  6. Sortir\n\n");
    printf("Escull una opcio: ");
}


/**
 * Sends a HELLO message and prints the server response.
 * @param sock socket used for the communication.
 */
void process_hello_operation(int sock)
{
    op_hello_rp hello_rp;
    char buffer[MAX_BUFF_SIZE];
    op_hello hello;

    bzero(buffer,MAX_BUFF_SIZE);
    stshort(MSG_HELLO, &hello.opcode);

    *((op_hello *) buffer) = hello;
    /* Send message to the server */
    if (send(sock, buffer, sizeof(op_hello),0) < 0) {
        perror("ERROR writing to socket");
        exit(1);
    }

    bzero(buffer,MAX_BUFF_SIZE);
    recv(sock, buffer, MAX_BUFF_SIZE, 0);

    hello_rp = *((op_hello_rp *)buffer);

    printf("%hu - %s\n",ldshort(&hello_rp.opcode),hello_rp.msg);


}

/**
 * Envia una petición para listar las reglas de filtrado del firewall.
 * @param sock socket que se utiliza para la comunicación.
 */
void process_list_operation(int sock)
{
    char buffer[MAX_BUFF_SIZE];
    int n;
    char *offset;
    op_list list_op;

    bzero(buffer,MAX_BUFF_SIZE);

    stshort(MSG_LIST, &list_op.opcode);

    /* Send message to the server */
    *((op_list *)buffer) = list_op;
    n = send(sock, buffer, sizeof(unsigned short),0);

    if (n < 0) {
        perror("ERROR writing to socket");
        exit(1);
    }

    printf("Firewall FORWARD rules:\n");
    printf("------------------------\n");

    /////////////////////////////////////
    bzero(buffer,MAX_BUFF_SIZE);
    recv(sock, buffer, MAX_BUFF_SIZE, 0);

    offset = buffer;
    unsigned short opcode = ldshort(buffer);
    unsigned short num_rules = ldshort(buffer + sizeof(unsigned short));

    /*op_rules rules_list_op = *((op_rules *)buffer);*/
    /*short opcode = ldshort(&rules_list_op.opcode);*/

    if(opcode == 4){

        /*offset = rules_list_op.rule_list; //start first rule*/
        offset += 2*sizeof(unsigned short);
        rule current_rule;

        int i;
        for(i=0 ; i < (int)num_rules;i++) {

            printf("%d: ",i+1);
            current_rule = *((rule*)offset);
            //SRC/DEST
            if(ldshort(&current_rule.src_dst_addr) == SRC){
                printf("SRC ");
            } else{
                printf("DST ");
            }

            //ADDRESS
            printf("%s", inet_ntoa(current_rule.addr));

            //MASK
            printf("\\%hu ",ldshort(&current_rule.mask));

            // PORT
            unsigned short port;
            port = ldshort(&current_rule.port);
            if(port != 0) {

                //SRC/DEST PORT
                unsigned short temp;
                temp = ldshort(&current_rule.src_dst_port);
                if(temp == SRC){
                    printf("SRC ");
                } else if(temp == DST) {
                    printf("DST ");
                }
                printf("%hu", port);

            }

            offset += sizeof(rule);
            printf("\n");
        }
        printf("Tot Rules: %hu\n",num_rules);
    }

}

/**
 * Añade o modifica los parametros de las reglas de filtrado de firewall.
 * @param new_rule regla que se quiere añadir o modificar.
 * @return true si se ha podido añadir o modificar la regla, en caso contrario devuelve false.
 */
int process_rule(rule *new_rule){

    printf("Introdueix la regla seguint el format:\n");
    printf("address src|dst Netmask [sport|dport] [port]\n");

    char full_rule[40];
    char * token;

    // Read user rule
    scanf(" %[^\n]s",full_rule);


    //================
    // ADDRESS
    //================
    int v_ip;
    token = strtok (full_rule," ");

    if(token != NULL) {
        struct in_addr address;
        v_ip = inet_aton(token, &address);

        if (v_ip == 0) {

            printf("%s No valid address\n", NOK_MSG);
            return 1;
        }

        new_rule->addr = address;
    }else{
        return 1;
    }

    //================
    // SRC/DST
    //================
    token = strtok(NULL, " ");
    if(token != NULL) {
        if (strcmp(token, SRC_STR) == 0) {

            //new_rule->src_dst_addr = (unsigned short) SRC;
            stshort(SRC,&new_rule->src_dst_addr);


        } else if (strcmp(token, DST_STR) == 0) {

            //new_rule->src_dst_addr = (unsigned short) DST;
            stshort(DST,&new_rule->src_dst_addr);

        } else {

            printf("%s No valid SRC/DST\n", NOK_MSG);
            return 1;
        }

    }else{
        return 1;
    }

    //================
    // MASK
    //================
    token = strtok(NULL, " ");
    if(token != NULL) {
        int mask = atoi(token);

        if ((mask <= 32) && (mask > 0)) {

            //new_rule->mask = (unsigned short) mask;
            stshort(mask,&new_rule->mask);

        } else {

            printf("%s No valid MASK\n", NOK_MSG);
            return 1;
        }

    } else{
        return 1;
    }
    //================
    // SPORT/DPORT
    //================
    token = strtok(NULL, " ");
    if(token != NULL) {

        if (strcmp(token, SRC_PORT_STR) == 0) {

            //new_rule->src_dst_port = (unsigned short) SRC;
            stshort(SRC,&new_rule->src_dst_port);

        } else if (strcmp(token, DST_PORT_STR) == 0) {

            //new_rule->src_dst_port = (unsigned short) DST;
            stshort(DST,&new_rule->src_dst_port);

        } else if (strcmp(token, "0") != 0) {

            printf("%s No valid SPORT/DPORT parameter\n", NOK_MSG);
            return 1;
        }

    }

    //================
    // SRC/DEST PORT
    //================
    token = strtok(NULL, " ");
    if(token != NULL) {
        int port = atoi(token);

        if ((port <= 65535) && (port >= 0)) {

            //new_rule->port = (unsigned short) port;
            stshort(port,&new_rule->port);

        } else {

            printf("%s No valid PORT\n", NOK_MSG);
            return 1;
        }

    }else{
        stshort(0,&new_rule->port);
    }

    return 0;

}


/**
 * Envia una petición para añadir una regla de filtrado del firewall.
 * @param sock socket que se utiliza para la comunicación.
 */
void process_add_operation(int sock)
{
    char buffer[MAX_BUFF_SIZE];
    int n;
    rule new_rule;

    bzero(buffer,MAX_BUFF_SIZE);
    stshort(MSG_ADD,buffer);

    int corr;
    corr = process_rule(&new_rule);

    if (corr == 0) {

        /* Send message to the server */
        *((rule *)(buffer+sizeof(short))) = new_rule;
        n = send(sock, buffer, sizeof(buffer), 0);

        if (n < 0) {
            perror("ERROR writing to socket");
            exit(1);
        }

        unsigned short code;
        bzero(buffer,MAX_BUFF_SIZE);
        recv(sock, buffer, 4, 0);
        code = ldshort(buffer);

        if(code == MSG_OK){
            printf("%s\n",OK_MSG);
        }else if (code == MSG_ERR){
            printf("%s%s\n",NOK_MSG,ERR_MSG_RULE);
        }else{
            printf("%s\n",ERR_MSG_DEFAULT);
        }
    }else{
        printf("%s\n",ERR_MSG_DEFAULT);
    }

}

/**
 * Envia una petición para modificar una regla de filtrado del firewall.
 * @param sock socket que se utiliza para la comunicación.
 */
void process_change_operation(int sock)
{
    char buffer[MAX_BUFF_SIZE];
    int id;
    op_change change_rule;

    bzero(buffer,MAX_BUFF_SIZE);
    stshort(MSG_CHANGE, &change_rule.opcode);

    // Read user change id
    printf("ID to change: ");
    scanf("%d",&id);
    if(id>0) {

        stshort(id,&change_rule.rule_id);
        printf("Changing id rule %hu\n", change_rule.rule_id);

        int corr;
        corr = process_rule(&change_rule.rule_change);

        if (corr == 0) {

            /* Send message to the server */
            *((op_change *)buffer) = change_rule;
            if (send(sock, buffer, sizeof(op_change), 0) < 0) {
                perror("ERROR writing to socket");
                exit(1);
            }

            bzero(buffer,MAX_BUFF_SIZE);
            recv(sock, buffer, 4, 0);

            unsigned short code;
            code = ldshort(buffer);

            if(code == MSG_OK){
                printf("%s\n",OK_MSG);
            }else if (code == MSG_ERR){
                printf("%s%s\n",NOK_MSG,ERR_MSG_RULE);
            }else{
                printf("%s\n",ERR_MSG_DEFAULT);
            }
        }

    }else{
        printf("ID should be bigger than 0: %s",ERR_MSG_RULE);
    }
}

/**
 * Envia una petición para eliminar una regla de filtrado del firewall.
 * @param sock socket que se utiliza para la comunicación.
 */
void process_delete_operation(int sock){

    char buffer[MAX_BUFF_SIZE];
    int id;

    op_delete delete_rule;

    bzero(buffer,MAX_BUFF_SIZE);
    stshort(MSG_DELETE, &delete_rule.opcode);

    // Read user change id
    printf("ID to delete: ");
    scanf("%d",&id);

    if(id>0) {

        stshort(id,&delete_rule.rule_id);

        /* Send message to the server */
        *((op_delete *)buffer) = delete_rule;
        if (send(sock, buffer, sizeof(op_delete), 0) < 0) {
            perror("ERROR writing to socket");
            exit(1);
        }

        bzero(buffer,MAX_BUFF_SIZE);
        recv(sock, buffer, MAX_BUFF_SIZE, 0);

        unsigned short code;
        code = ldshort(buffer);

        if(code == MSG_OK){
            printf("%s\n",OK_MSG);
        }else{
            printf("%s%s\n",NOK_MSG,ERR_MSG_RULE);
        }

    }else{
        printf("ID should be bigger than 0: %s",ERR_MSG_RULE);
    }


}

/**
 * Envia una petición para eliminar todas las reglas de filtrado del firewall.
 * @param sock socket que se utiliza para la comunicación.
 */
void process_flush_operation(int sock){

    char buffer[MAX_BUFF_SIZE];
    op_flush flush_rule;

    bzero(buffer,MAX_BUFF_SIZE);
    stshort(MSG_FLUSH2, &flush_rule.opcode);

    /* Send message to the server */
    *((op_flush *)buffer) = flush_rule;
    if (send(sock, buffer, sizeof(op_flush), 0) < 0) {
        perror("ERROR writing to socket");
        exit(1);
    }

    bzero(buffer,MAX_BUFF_SIZE);
    recv(sock, buffer, MAX_BUFF_SIZE, 0);

    unsigned short code;
    code = ldshort(buffer);

    if(code == MSG_OK){
        printf("%s\n",OK_MSG);
    }else{
        printf("%s%s\n",NOK_MSG,ERR_MSG_RULE);
    }

}

/**
 * Closes the socket connected to the server and finishes the program.
 * @param sock socket used for the communication.
 */
void process_exit_operation(int sock)
{
    char buffer[MAX_BUFF_SIZE];

    bzero(buffer,MAX_BUFF_SIZE);
    stshort(MSG_FINISH, buffer);

    /* Send message to the server */
    if (send(sock, buffer, sizeof(unsigned short),0) < 0) {
        perror("ERROR writing to socket");
        exit(1);
    }
}

/**
 * Function that process the menu option set by the user by calling
 * the function related to the menu option.
 * @param s The communications socket
 * @param option the menu option specified by the user.
 */
void process_menu_option(int s, int option)
{
    switch(option){
        // Opció HELLO
        case MENU_OP_HELLO:
            process_hello_operation(s);
            break;
        case MENU_OP_LIST_RULES:
            process_list_operation(s);
            break;
        case MENU_OP_ADD_RULE:
            process_add_operation(s);
            break;
        case MENU_OP_CHANGE_RULE:
            process_change_operation(s);
            break;
        case MENU_OP_DEL_RULE:
            process_delete_operation(s);
            break;
        case MENU_OP_FLUSH:
            process_flush_operation(s);
            break;
        case MENU_OP_EXIT:
            process_exit_operation(s);
            exit(0);
            break;
        default:
            printf("Invalid menu option\n");
    }
}


int main(int argc, char *argv[]){

    int sockfd;
    unsigned short port;
    char *hostName;
    int menu_option = 0;

    port = getPort(argc, argv);
    hostName = getHost(argc, argv);

    //Checking that the host name has been set.Otherwise the application is stopped.
    if(hostName == NULL){
        perror("No s'ha especificat el nom del servidor\n\n");
        return -1;
    }

    /* Create a socket */
    sockfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (sockfd < 0) {
        perror("ERROR opening socket");
        exit(1);
    }

    /* Set socket parameters */
    struct sockaddr_in serv_addr;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_family = AF_INET;

    setaddrbyname(&serv_addr, hostName);

    /* Connect to the server */
    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("ERROR connecting");
        exit(1);
    }

    do{
        print_menu();
        scanf("%d",&menu_option);
        printf("\n\n");
        process_menu_option(sockfd, menu_option);

    }while(menu_option != MENU_OP_EXIT);

    return 0;
}
