/***************************************************************************
 *            fwServer.h
 *
 *  Copyright  2016  mc
 *  <mcarmen@<host>>
 ****************************************************************************/
 #include "common.h"

 #define MAX_QUEUED_CON 10 // Max number of connections queued

/**
 * Structures to implement the firewall rules
 * ==========================================
 */

 struct fw_rule
 {
    rule rule;
    struct fw_rule * next_rule;
 };

 struct FORWARD_chain
 {
   int num_rules;
   struct fw_rule * first_rule;
 };


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
 * Function that sends a HELLO_RP to the  client
 * @param sock the communications socket
 */
void process_HELLO_msg(int sock);

/**
 * Función que devuelve el resultado de la operación efectuada.
 * @param opcode codigo con el resultado de la operación.
 */
void msg_return(int sock, int opcode);

/**
 * Function that sends a HELLO_RP to the client
 * @param sock the communications socket
 */
void process_HELLO_msg(int sock);


/**
 * Función que envia al cliente una lista con las reglas del firewall.
 * @param sock socket que se utiliza para la comunicación.
 * @param chain la cadena con que contiene las reglas de filtrado.
 */
void process_RULES(int sock, struct FORWARD_chain *chain);

/**
 * Función que agregra una nueva regla a la lista con las reglas del firewall.
 * @param sock socket que se utiliza para la comunicación.
 * @param chain la cadena con que contiene las reglas de filtrado.
 * @param buffer buffer con la información perteneciente a la nueva regla que se desea agregar a la lista.
 */
void process_ADD(int sock, struct FORWARD_chain *chain, rule buffer);

/**
 * Función que modifica la regla de firewall escogida de la lista.
 * @param sock socket que se utiliza para la comunicación.
 * @param chain la cadena con que contiene las reglas de filtrado.
 * @param buffer buffer con la información perteneciente a la regla que se desea modificar.
 */
void process_CHANGE(int sock, struct FORWARD_chain *chain, op_change *buffer);

/**
 * Función que elimina la regla escogida de la lista con las reglas del firewall.
 * @param sock socket que se utiliza para la comunicación.
 * @param chain la cadena con que contiene las reglas de filtrado.
 * @param buffer buffer con la información perteneciente a la regla que se desea eliminar.
 */
void process_DELETE(int sock, struct FORWARD_chain *chain, op_delete *delete_rule);

/**
 * Función que elimina todas las reglas de la lista..
 * @param sock socket que se utiliza para la comunicación.
 * @param chain la cadena con que contiene las reglas de filtrado.
 */
void process_FLUSH(int sock, struct FORWARD_chain *chain);

 /**
 * Receives and process the request from a client.
 * @param the socket connected to the client.
 * @param chain the chain with the filter rules.
 * @return 1 if the user has exit the client application therefore the
 * connection whith the client has to be closed. 0 if the user is still
 * interacting with the client application.
 */
int process_msg(int sock, struct FORWARD_chain *chain);
