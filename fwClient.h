/***************************************************************************
 *            fwClient.h
 *
 *  Copyright  2016  mc
 *  <mcarmen@<host>>
 ****************************************************************************/
#include "common.h"

#define MENU_OP_HELLO 0
#define MENU_OP_LIST_RULES 1
#define MENU_OP_ADD_RULE 2
#define MENU_OP_CHANGE_RULE 3
#define MENU_OP_DEL_RULE 4
#define MENU_OP_FLUSH 5
#define MENU_OP_EXIT 6


#define OK_MSG "Operació finalitzada amb èxit"
#define NOK_MSG "L'operació no s'ha pogut dur a terme degut a: "

#define MAX_ERR_MSG_SIZE 100
#define MAX_ADDR_SIZE 16 //maximum size of an ip addr in decimal dotted quad format + \0
#define MAX_RULE_SIZE 100 //maximum size of an rule in a string format.
#define MAX_SRC_DST_STR_SIZE 6 //maximum size for the string indicating src or dest.
#define MAX_OK_ERR_MSG_SIZE 6 //maximum size for a OK or ERROR message.

#define ERR_MSG_RULE "La regla no existeix."
#define ERR_MSG_DEFAULT "Hi ha hagut algun problema."

#define ERR_RULE 1

#define IP_STR "IP"
#define NETID_STR "netID"
#define SRC_STR "src"
#define DST_STR "dst"
#define SRC_PORT_STR "sport"
#define DST_PORT_STR "dport"


/**
 * Function that sets the field addr->sin_addr.s_addr from a host name
 * address.
 * @param addr struct where to set the address.
 * @param host the host name to be converted
 * @return -1 if there has been a problem during the conversion process.
 */
int setaddrbyname(struct sockaddr_in *addr, char *host);

/**
 * Returns the port specified as an application parameter or the default port
 * if no port has been specified.
 * @param argc the number of the application arguments.
 * @param an array with all the application arguments.
 * @return  the port number from the command line or the default port if
 * no port has been specified in the command line. Returns -1 if the application
 * has been called with the wrong parameters.
 */
int getPort(int argc, char* argv[]);

/**
 * Returns the host name where the server is running.
 * @param argc the number of the application arguments.
 * @param an array with all the application arguments.
 * @Return Returns the host name where the server is running.<br />
 * Returns -1 if the application has been called with the wrong parameters.
 */
 char * getHost(int argc, char* argv[]);

 /**
 * Shows the menu options.
 */
void print_menu();

/**
 * Sends a HELLO message and prints the server response.
 * @param sock socket used for the communication.
 */
void process_hello_operation(int sock);

/**
 * Envia una petición para listar las reglas de filtrado del firewall.
 * @param sock socket que se utiliza para la comunicación.
 */
void process_list_operation(int sock);

/**
 * Añade o modifica los parametros de las reglas de filtrado de firewall.
 * @param new_rule regla que se quiere añadir o modificar.
 * @return true si se ha podido añadir o modificar la regla, en caso contrario devuelve false.
 */
int process_rule(rule *new_rule);

/**
 * Envia una petición para añadir una regla de filtrado del firewall.
 * @param sock socket que se utiliza para la comunicación.
 */
void process_add_operation(int sock);

/**
 * Envia una petición para modificar una regla de filtrado del firewall.
 * @param sock socket que se utiliza para la comunicación.
 */
void process_change_operation(int sock);

/**
 * Envia una petición para eliminar una regla de filtrado del firewall.
 * @param sock socket que se utiliza para la comunicación.
 */
void process_delete_operation(int sock);

/**
 * Envia una petición para eliminar todas las reglas de filtrado del firewall.
 * @param sock socket que se utiliza para la comunicación.
 */
void process_flush_operation(int sock);

/**
 * Closes the socket connected to the server and finishes the program.
 * @param sock socket used for the communication.
 */
void process_exit_operation(int sock);

/**
 * Function that process the menu option set by the user by calling
 * the function related to the menu option.
 * @param s The communications socket
 * @param option the menu option specified by the user.
 */
void process_menu_option(int s, int option);

