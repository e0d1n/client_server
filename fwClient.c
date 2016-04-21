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

    printf("in getHost host: %s\n", hostName); //!!!!!!!!!!!!!!
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
    struct hello_rp hello_rp;

    char buffer[MAX_BUFF_SIZE];
    int n;

    unsigned short code = MSG_HELLO;

    bzero(buffer,MAX_BUFF_SIZE);
    stshort(code, buffer);

    /* Send message to the server */
    n = send(sock, buffer, sizeof(unsigned short),0);


    if (n < 0) {
        perror("ERROR writing to socket");
        exit(1);
    }

    bzero(buffer,MAX_BUFF_SIZE);
    recv(sock, buffer, sizeof(buffer), 0);

    hello_rp.opcode = ldshort(buffer);
    memcpy(hello_rp.msg,(buffer+sizeof(unsigned short)),12);

    printf("Recieved: |%hu|%s|\n",hello_rp.opcode,hello_rp.msg);


}

void process_list_operation(int sock)
{
    char buffer[MAX_BUFF_SIZE];
    int n;
    char *offset;
    unsigned short opcode = MSG_LIST;

    bzero(buffer,MAX_BUFF_SIZE);
    stshort(opcode, buffer);

    /* Send message to the server */
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
    opcode = ldshort(offset);


    if(opcode == 4){

        offset += sizeof(unsigned short);

        unsigned short tot_rules;
        unsigned short temp;
        tot_rules = (unsigned short) *offset;

        offset += sizeof(unsigned short); //start first rule
        rule new_rule;

        int i;
        for(i=0;i<(int) tot_rules ;i++) {

            new_rule = *((rule *) offset);
            printf("%d: ",i+1);

            //ADDRESS
            printf("%s ", inet_ntoa(new_rule.addr));
            offset += 4;

            //SRC/DEST
            temp = *offset;

            if(temp == SRC){
                printf("SRC ");
            } else{
                printf("DST ");
            }
            offset += sizeof(unsigned short);

            //MASK
            temp = *offset;
            printf("%hu ",temp);
            offset += sizeof(unsigned short);

            //SRC/DEST PORT
            temp = *offset;
            if(temp == SRC){
                printf("SRC ");
            } else{
                printf("DST ");
            }
            offset += sizeof(unsigned short);

            // PORT
            temp = *offset;
            printf("%hu\n",temp);
            offset += sizeof(unsigned short);
            //offset += sizeof(rule);
        }
        printf("Tot Rules: %hu",tot_rules);
    }

}
/**
 * Process a single add/change rule and store it to
 * @param buffer
 */

int process_rule(char *buffer){

    /*
    4 bytes     2 bytes    2 bytes    2 bytes       2 bytes
    --------------------------------------------------------
    | net_ID/IP | src/dst  | net_mask | sport/dport | port |
    --------------------------------------------------------

    typedef struct FORWARD_rule{
        struct in_addr addr;
        unsigned short src_dst_addr;
        unsigned short mask;
        unsigned short src_dst_port;
        unsigned short port;
    }rule;
     */

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

    struct in_addr address;
    v_ip = inet_aton(token, &address);

    if(v_ip == 0){

        printf("%s No valid address\n",NOK_MSG);
        return 1;
    }
    memcpy(buffer,&address, 4);
    buffer+=4;

    //================
    // SRC/DST
    //================
    token = strtok (NULL, " ");
    if(strcmp(token,SRC_STR) == 0){

        *buffer = (unsigned short) SRC;


    }else if(strcmp(token,DST_STR) == 0){

        *buffer = (unsigned short) DST;

    }else{

        printf("%s No valid SRC/DST\n",NOK_MSG);
        return 1;
    }

    buffer+= sizeof(unsigned short);

    //printf("%s",inet_ntoa(new_rule->addr));

    //================
    // MASK
    //================

    token = strtok (NULL, " ");
    int mask = atoi(token) ;

    if((mask <= 32) && (mask >= 0)){

        *buffer = (unsigned short) mask;

    } else{

        printf("%s No valid MASK\n",NOK_MSG);
        return 1;
    }
    buffer+= sizeof(unsigned short);

    //================
    // SPORT/DPORT
    //================

    token = strtok (NULL, " ");

    if(strcmp(token,SRC_PORT_STR) == 0){

        *buffer = (unsigned short) SRC;

    }else if(strcmp(token,DST_PORT_STR) == 0){

        *buffer = (unsigned short) DST;

    }else{

        printf("%s No valid SPORT/DPORT parameter\n",NOK_MSG);
        return 1;
    }
    buffer+= sizeof(unsigned short);

    //================
    // SRC/DEST PORT
    //================

    token = strtok (NULL, " ");
    int port = atoi(token) ;

    if((port <= 65535) && (port > 0)){
        *buffer = (unsigned short) port;

    } else{

        printf("%s No valid PORT\n",NOK_MSG);
        return 1;
    }

    return 0;

}

void process_add_operation(int sock)
{
    char buffer[MAX_BUFF_SIZE];
    int n;
    char *offset = buffer;

    bzero(buffer,MAX_BUFF_SIZE);

    unsigned short code = MSG_ADD;
    stshort(code, offset);
    offset += sizeof(unsigned short);


    int corr;
    ///////////////////////////////////
    corr = process_rule(offset);
    //////////////////////////////////

    if (corr == 0) {
        /* Send message to the server */
        n = send(sock, buffer, sizeof(buffer), 0);

        if (n < 0) {
            perror("ERROR writing to socket");
            exit(1);
        }
    }
    //TODO: check server response

}

void process_change_operation(int sock)
{
    char buffer[MAX_BUFF_SIZE];
    int n,id;
    char *offset = buffer;

    bzero(buffer,MAX_BUFF_SIZE);

    unsigned short code = MSG_CHANGE;
    stshort(code, offset);
    offset += sizeof(unsigned short);


    // Read user change id
    printf("ID to change: ");
    scanf("%d",&id);
    if(id>0) {
        *offset = (unsigned short) id;
        printf("Changing id rule %hu\n", (unsigned short) *offset);
        offset += sizeof(unsigned short);

        int corr;
        ///////////////////////////////////
        corr = process_rule(offset);
        //////////////////////////////////

        if (corr == 0) {
            /* Send message to the server */
            n = send(sock, buffer, sizeof(buffer), 0);

            if (n < 0) {
                perror("ERROR writing to socket");
                exit(1);
            }
        }
    }else{
        printf("%s",ERR_MSG_RULE);
    }

    //TODO: check server response


}

void process_delete_operation(int sock){

    char buffer[MAX_BUFF_SIZE];
    int n,id;
    char *offset = buffer;

    bzero(buffer,MAX_BUFF_SIZE);

    unsigned short code = MSG_DELETE;
    stshort(code, offset);
    offset += sizeof(unsigned short);


    // Read user change id
    printf("ID to change: ");
    scanf("%d",&id);
    if(id>0) {
        *offset = (unsigned short) id;

        /* Send message to the server */
        n = send(sock, buffer, sizeof(buffer), 0);

        if (n < 0) {
            perror("ERROR writing to socket");
            exit(1);
        }
    }else{
        printf("%s",ERR_MSG_RULE);
    }


}

/**
 * Closes the socket connected to the server and finishes the program.
 * @param sock socket used for the communication.
 */
void process_exit_operation(int sock)
{
    char buffer[MAX_BUFF_SIZE];
    int n;

    unsigned short code = 9;

    bzero(buffer,MAX_BUFF_SIZE);
    stshort(code, buffer);

    /* Send message to the server */
    n = send(sock, buffer, sizeof(unsigned short),0);

    if (n < 0) {
        perror("ERROR writing to socket");
        exit(1);
    }

    exit(0);
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
            break;
        case MENU_OP_EXIT:
            process_exit_operation(s);
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
    struct sockaddr_in serv_addr;

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

    serv_addr.sin_port = htons(port);
    serv_addr.sin_family = AF_INET;
    //inet_aton(&hostName,&serv_addr.sin_addr); //WORKING

    setaddrbyname(&serv_addr, hostName);

    /* Connect to the server */
    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("ERROR connecting");
        exit(1);
    }


    do{
        print_menu();
        // getting the user input.
        scanf("%d",&menu_option);
        printf("\n\n");
        process_menu_option(sockfd, menu_option);

    }while(menu_option != MENU_OP_EXIT); //end while(opcio)

    return 0;
}
