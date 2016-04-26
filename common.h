/***************************************************************************
 *            common.h
 *
 *  Copyright  2016  mc
 *  <mcarmen@<host>>
 ****************************************************************************/

#include <unistd.h> //per tipus com el socklen_t
#include <netdb.h> //pel gethostbyname
#include <errno.h> //per gestionar errors
#include <sys/types.h> //per tipus com el uint32_t
#include <netinet/in.h> //pel INADDR_ANY
#include <arpa/inet.h> //per la funció inet_aton
#include <sys/socket.h> //per la creació de sockets


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUFF_SIZE 1024

#define DEFAULT_PORT 2222

#define MSG_HELLO 1
#define MSG_HELLO_RP 2
#define MSG_LIST 3
#define MSG_RULES 4
#define MSG_ADD 5
#define MSG_CHANGE 6
#define MSG_DELETE 7
#define MSG_FLUSH2 8
#define MSG_FINISH 9
#define MSG_OK 10
#define MSG_ERR 11

#define ERR_RULE 1

#define SRC 0
#define DST 1

typedef enum{
  FALSE = 0,
  TRUE = 1
}bool;


// Macros per afegir i extreure un short d'un missatge
#define stshort(sval, addr) ( *((short *)(addr))=htons(sval) )
#define ldshort(addr) ( ntohs(*((short *)(addr)) ) ) 

/**
 * Structures directly mapped with a message to be sent or received
 * ================================================================
 */


//Structures directly mapped with a message to be sent or received
//Estructures per encapsular les dades del missatge

typedef struct HELLO{
	unsigned short opcode;
}op_hello;

/*
              2 bytes  11 bytes       1 byte
              ------------------------------
HELLO_RP      |  2     | Hello World | 0   | 
              ------------------------------
*/
typedef struct HELLO_RP{
	unsigned short opcode;
	char msg[12];
}op_hello_rp;

typedef struct LIST{
	unsigned short opcode;
}op_list;


/*
4 bytes     2 bytes    2 bytes    2 bytes       2 bytes
--------------------------------------------------------
| net_ID/IP | src/dst  | net_mask | sport/dport | port |
--------------------------------------------------------
*/
typedef struct FORWARD_rule{
  struct in_addr addr;
  unsigned short src_dst_addr;
  unsigned short mask;
  unsigned short src_dst_port;
  unsigned short port;
}rule;

typedef struct RULES{
	unsigned short opcode;
	unsigned short num_rules;
	rule rule_list[(MAX_BUFF_SIZE-4)/ sizeof(rule)];
}op_rules;

typedef struct ADD{
	unsigned short opcode;
	rule rule_add;
}op_add;

typedef struct CHANGE{
	unsigned short opcode;
	unsigned short rule_id;
	rule rule_change;
}op_change;

typedef struct DELETE{
	unsigned short opcode;
	unsigned short rule_id;
}op_delete;

typedef struct FLUSH{
	unsigned short opcode;
}op_flush;

typedef struct OP_OK{
	unsigned short opcode;
}op_ok;

typedef struct OP_ERR{
	unsigned short opcode;
	unsigned short error_code;
}op_err;
