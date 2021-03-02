/****************************************************************************
*
*	Revision History:
*
*	Date			Rev		By		Description of Revision
*
*	18-APR-2018		0.01	GAN		Initial release.
*
*	31-JUL-2018		0.02	GAN		Added Publish message count and 
*									Receive(Subscribe) message count.
*****************************************************************************/

#ifndef MQTT_H
#define MQTT_H

#include "mosquitto.h"
#include "nxjson.h"
#include "general.h"
#include "configSelection.h"
#include "jwt.h"

/* Constants */
#define SSL_VERIFY_NONE 			0
#define SSL_VERIFY_PEER 			1

#define MQTT_MIN_DOWNLOAD_SIZE 		16
#define MAX_STR_LEN 				255

#define MAX_PUBLISH 				4
#define MAX_SUBSCRIBE 				4

#define MQTT_RETRY 					3
#define INTV_SEC 					2
#define RETRY_INTV_SEC 				10
#define US_1_MS		 				10000

#define	DEBUG						TRUE

#define SET_ST_EV(state,event)		nextMqttState = state; nextMqttEvent = event
#define SET_STATE(state)			nextMqttState = state
#define SET_EVENT(event)			nextMqttEvent = event
#define	IS_STATE(state)				(nextMqttState == state)? TRUE : FALSE

#define	JSON_ARRAY_KEY				"{\"ArrayOfReg\":["

/* Status Register Bits */		/* Index */
#define	GET_CONFIG					0		//Flag 1
#define	BROKER_CONNECT				1		//Flag 2
#define	MQTT_LESS_CONFIG			2		//Flag 3
#define	MQTT_INVALID_MSG			3		//Flag 4
#define	UNABLE_TO_RECONNECT			4		//Flag 5
#define	EMPTY_MSG					5		//Flag 6
#define	MSG_CPY_FAILED				6		//Flag 7
#define	SUBSCRIBE_CALL_FAILED		7		//Flag 8
#define	PUBLISH_CALL_FAILED			8		//Flag 9

#define	BROKER_CONNECT_CODE			32
#define	BROKER_DISCONNECT_CODE		64
#define	BROKER_TOTAL_PUP_MSG		96
#define	BROKER_TOTAL_SUP_MSG		128

/* Status Value */
#define	OUT_OF_MEMORY				256
#define	UNAME_PASSWD_SET_FAILED		257
#define	TLS_SET_FAILED				258
#define	TLS_OPT_SET_FAILED			259
#define	BROKER_CONNECT_CALL_FAILED	260
#define	NW_LOOP_START_FAILED		261

#if GOOGLE
#define	KW_PROJID		"projects/"
#define	KW_LOC			"/locations/"
#define	KW_REGIS		"/registries/"
#define	KW_DEV			"/devices/"
#define	KW_EVENT		"/events"
#endif

#if ATNT
#define	KW_M2X			"m2x/"
#define	KW_REQUESTS		"/requests"
#endif

typedef struct mosquitto* 			mqttInstance;
typedef struct mosquitto_message 	mqttMsg;

/** Union **/
typedef union
{
	INT8	int8Val;
	UINT8	uInt8Val;
	INT16	int16Val;
	UINT16 	uInt16Val;
	INT32	int32Val;
	UINT32	uInt32Val;
	FP32	floatVal;
	CHAR	character;
	CHAR	strBuf[MAX_STR_LEN];
}REG_VALUE;

/** Enums **/
typedef enum
{
	STATE_LIB_INIT = 0,
	STATE_LIB_DEINIT,
	STATE_GET_CONFIG,
	STATE_CONNECT,
	STATE_PUBLISH,
	STATE_SUBSCRIBE,
	STATE_PROC_MSG,
	STATE_DISCONNECT,
	STATE_IDLE
}E_MQTT_STATES;

typedef enum
{
	EVENT_PROC_MSG = 0,
	EVENT_PUBLISH,
	EVENT_SUBSCRIBE,
	EVENT_REINIT,
	EVENT_CONNECT_SENT,
	EVENT_DISCONNECT_SENT,
	EVENT_EMPTY
}E_MQTT_EVENTS;

typedef enum
{
	PUBLISHER = 1,
	SUBSCRIBER,
	PUB_SUB_BOTH
}E_CLIENT_TYPE;

typedef enum
{
	CERT_KEY = 1,
	PRESHARED_KEY
}E_SSL_TYPE;

typedef enum
{
	DATA_TYPE_BOOLEAN = 1,
	DATA_TYPE_SINT,		//8bit
	DATA_TYPE_USINT,	//8bit
	DATA_TYPE_INT,		//16bit
	DATA_TYPE_UINT,		//16bit
	DATA_TYPE_DINT,		//32bit
	DATA_TYPE_UDINT,	//32bit
	DATA_TYPE_REAL,		//32bit
	DATA_TYPE_STRING
}REG_DATA_TYPES;

/** MQTT Configure Structure **/
typedef struct
{
	UINT32			regToken;
	UINT16			regLength;
	REG_DATA_TYPES	regDataType;
	UINT8			unused1;
}REG_INFO;

typedef struct
{
	BOOL			isBrokerConnected;		//TRUE or FALSE
	BOOL			connCmdSent;			//TRUE(SUCCESS) or FALSE(FAILURE)
	BOOL			disConnCmdSent;			//TRUE(SUCCESS) or FALSE(FAILURE)
	UINT8			unused3;
}CLIENT_STATUS;

typedef struct
{
	BOOL			publishDataStatus;		//TRUE(SUCCESS) or FALSE(FAILURE)
	BOOL			publishCmdSent;			//TRUE(SUCCESS) or FALSE(FAILURE)
	BOOL			subscribeDataStatus;	//TRUE(SUCCESS) or FALSE(FAILURE)
	BOOL			subscribeCmdSent;		//TRUE(SUCCESS) or FALSE(FAILURE)
	BOOL			unSubscribeDataStatus;	//TRUE(SUCCESS) or FALSE(FAILURE)
	BOOL			subDataProcStatus;		//TRUE(PROCESSED) or FALSE(NOT PROCESSED)
	UINT8			unused1;
	UINT8			unused2;
}MSG_STATUS;

typedef struct
{
	CHAR 			*topic;
	CHAR			*msg;
	INT 			msgLen;
	INT 			qos;
	INT 			msgId;
	INT32			retryCnt;
	BOOL 			retain;
	BOOL			dataLoaded;				//if TRUE ,data ready to publish
	UINT8			publishType;			//1 - Periodic or 2 - Event
	UINT32			pubEventReg;			//Token for event/trigger
	UINT32			perInterval;
	UINT32			perIntervalTime;		//Timeout for periodic Interval
	REG_INFO		regDataInfo;
	MSG_STATUS		msgStatus;
	UINT8			unused1;
}PUB_MQTT_MSG;

typedef struct
{
	const CHAR 		*topic;
	INT 			qos;
	INT 			msgId;
	INT32			retryCnt;
	UINT32			subTickTime;		//Timeout for SUBSCRIBE
	BOOL			dataLoaded;			//if TRUE ,data ready to process
	mqttMsg			mqttMessage;
	MSG_STATUS		msgStatus;
	UINT8			unused1;
	UINT8			unused2;
	UINT8			unused3;
}SUB_MQTT_MSG;

typedef struct
{
	BOOL			withSsl; //TRUE(yes) or FALSE(No)
	E_SSL_TYPE		sslType; //1 - CERT_KEY , 2 - PRESHARED_KEY
	BOOL			caOnly; /*ADDED 1*/ /* TRUE - get only rootCa file,FALSE - get rootCa,client_cert,client_key all*/
	CHAR			*caCrtFile;
	CHAR			*clientCrtFile;
	CHAR			*clientKeyFile;
	CHAR			*pemPassword;
	CHAR			*tlsVersion;
	CHAR			*sslCiphers; //refer this command "openssl ciphers"
	CHAR 			*presharedKey; //should be hex string value
	CHAR 			*identity;
	BOOL			insecure; /*ADDED 1*/ /* TRUE - Enable,FALSE - Disable*/
}SSL_TLS_CONFIG;

/** This configure for each broker connection. **/
typedef struct
{
	BOOL			enable;				//if it is TRUE , then only client will initiate
	mqttInstance	mqttInst;
	CHAR			*mqttConnName; 		//Connection name for each broker connection
	CHAR			*mqttBrokerIp;
	CHAR			*mqttBrokerUname;
	CHAR			*mqttBrokerPasswd;
	CHAR			*clientId;			//if clientId is NULL , cleanSession should be TRUE
	INT				keepAlive;			//in sec
	UINT32			mqttBrokerPort;
	BOOL			cleanSession; 		//TRUE or False
	E_CLIENT_TYPE	clientType;
	CLIENT_STATUS	clientStatus;
	PUB_MQTT_MSG	pubMqttMsg[MAX_PUBLISH];
	SUB_MQTT_MSG	subMqttMsg[MAX_SUBSCRIBE];
	SSL_TLS_CONFIG	sslTlsConfig;
	INT32			retryCnt;  			//connect retry count
	UINT32			statusRegToken;
	UINT32			conTickTime;		//Timeout for CONACK
	UINT32			disConTickTime;		//Timeout for DISCONACK
	UINT32			totalPubCount;		//This is the count of publish entry added by user out of MAX_PUBLISH
	UINT32			totalSubCount;		//This is the count of subscribe entry added by user out of MAX_SUBSCRIBE
	UINT32			totalPubMsgCount;	//This is the count of published messages /*v0.02*/
	UINT32			totalSubMsgCount;	//This is the count of Received messages /*v0.02*/
	UINT8			unused1;
}MQTT_CONFIG;

/** Configure structure from Cscape  **/
typedef struct
{
	UINT32	dwPubrefStart;
	UINT32	dwPubCount;
	UINT32	dwPubTypeOffset;
	UINT32	dwPubTypeLength;

	UINT32	dwPubTopicNameOffset;
	UINT32	dwPubTopicNameLength;
	UINT32	dwPubQosBlockSize;
	UINT32	dwPubRetained;
	UINT32	dwPubPeriodicChk;
	UINT32	dwPubPeriodicTime;
	UINT32	dwPubTopicTrigger;
}PUBLISH_TOPICS;

typedef struct
{
	UINT32	dwSubTopicNameOffset;
	UINT32	dwSubTopicNameLength;
	UINT32	dwSubQosBlockSize;
}SUBSCRIBE_TOPICS;

typedef struct
{
	UINT32	dwMQTTDataSize; //This is not for FW
	UINT32	dwStringTableOffset;
	
	/* Broker IP */
	UINT32	dwMQTTServerIPOffset;
	UINT32	dwMQTTServerIPLength;
	/* User NAme */
	UINT32	dwMQTTUserNameOffset;
	UINT32	dwMQTTUserNameLength;
	/* Password */
	UINT32	dwMQTTPasswordOffset;
	UINT32	dwMQTTPasswordLength;
	/* Client ID */
	UINT32	dwMQTTClientIdOffset;
	UINT32	dwMQTTClientIdLength;

	UINT32	dwMQTTPortNumber;
	UINT32	dwMQTTKeepAlive;
	UINT32	dwMQTTCleanSession;
	UINT32	dwMQTTClientType;
	
	/* Broker/Connection Name */
	UINT32	dwMQTTRemoteNodeNameOffset;
	UINT32	dwMQTTRemoteNodeNameLength;
	/* Status Register - Token Only */
	UINT32	dwMQTTStatus;
	/* Enable(Trigger) Register - Token Only */
	UINT32	dwMQTTTrigger;
	/* TLS */
	UINT32	dwMQTTEnableSSL_TLS; //0 or 1
	UINT32	dwMQTTProtType; // 1 - tlsv1, 2 - tlsv1.1, 3 - tlsv1.2
	
	UINT32	dwMQTTCACertFileChk;		//0 or 1 - cafileonly option
	UINT32	dwMQTTSLFSGNCertFileChk;	//0 or 1 - cafile and client files option
	/* CAfile DataString */
	UINT32	dwMQTTCACertFileStrOffset;
	UINT32	dwMQTTCACertFileStrLength;
	/* CAfile and clientFile DataString */
	UINT32	dwMQTTSelfSignCACertFileStrOffset;
	UINT32	dwMQTTSelfSignCACertFileStrLength;
	UINT32	dwMQTTSelfSignClntCACertFileStrOffset;
	UINT32	dwMQTTSelfSignClntCACertFileStrLength;
	UINT32	dwMQTTSelfSignClntKeyFileStrOffset;
	UINT32	dwMQTTSelfSignClntKeyFileStrLength;
	UINT32	dwMQTTSelfSignClntKeyPasswordOffset;
	UINT32	dwMQTTSelfSignClntKeyPasswordLength;
	
	/* Data Publish */
	UINT32	dwMQTTNoOfPublishTopics;
	UINT32  dwMQTTNoOfSubcribeTopics;
	UINT32	UnUsed1;
	UINT32	UnUsed2;

	PUBLISH_TOPICS	publishTopicsData[MAX_PUBLISH];
	SUBSCRIBE_TOPICS subscribeTopicsData[MAX_SUBSCRIBE];
} MQTT_COMPILED_FORMAT;

#if GOOGLE
/* JWT type of Authentication */
typedef struct
{
	CHAR 		*iat; /* Issued At */
	CHAR 		*exp; /* Expiration */
	CHAR 		*aud; /* Audience (cloud project ID) */
	CHAR 		*privateKeyPath; /* a secret key (such as an rsa_private.pem file) using the algorithm you defined in the header */
	jwt_alg_t	jwtAlgType; /* jwt.h */
	CHAR 		*jwtOutput; /* This will be output of libjwt and it goes to password of MQTT Broker */
	UINT16		expTime; /* JWTs expiry time in sec ( max allowed 86400(24 hrs) ) */
	UINT16		secsFromIssue;
	time_t 		iatTimeInsec;
}JWT_INFO;

typedef struct
{
	CHAR 		*projectId;
	CHAR 		*regisId;
	CHAR 		*deviceID;
	CHAR 		*region;
	JWT_INFO	jwtInfos;
}GOOGLE_IOT_CONFIG;
#endif

#if ATNT
typedef struct
{
	CHAR 	*deviceName;
	CHAR 	*deviceID;
	CHAR 	*primaryEndPoint;
	CHAR 	*primaryApiKey;
	CHAR 	*streamID;
	UINT32	msgIdCnt;
}ATNT_IOT_CONFIG;
#endif

#if SPARKPLUG
typedef struct
{
	BOOL enable; /* TRUE - enable , FALSE - Disable */
	
}SP_MAIN_CONFIG;

#endif

/** Function Prototype **/
VOID mqttLibInit(VOID);
VOID mqttLibDeinit(VOID);
BOOL mqttConnect(MQTT_CONFIG *mqttConf);
BOOL mqttDisconnect(MQTT_CONFIG *mqttConf);
BOOL mqttPublish(MQTT_CONFIG *mqttConf,UINT32 pubMsgIndex);
BOOL mqttSubscribe(MQTT_CONFIG *mqttConf,UINT32 subMsgIndex);
BOOL mqttUnsubscribe(MQTT_CONFIG *mqttConf,UINT32 subMsgIndex);

/** Callbacks **/
VOID connectCallback(struct mosquitto *mosq, VOID *userdata, INT result);
VOID subscribeCallback(struct mosquitto *mosq, VOID *userdata, INT mid, INT qosCount, const INT *grantedQos);
VOID messageCallback(struct mosquitto *mosq, VOID *userdata, const struct mosquitto_message *message);
VOID publishCallback(struct mosquitto *mosq, VOID *userdata, INT mid);
VOID logCallback(struct mosquitto *mosq, VOID *userdata, INT level, const CHAR *str);
VOID disconnectCallback(struct mosquitto *mosq, VOID *userdata, INT reasonCode);
INT tlsPwdCallback(CHAR *buf, INT size, INT rwflag, VOID *userdata);

/** main.c **/

#endif 	// end of #ifndef MQTT_H

/* EOF */