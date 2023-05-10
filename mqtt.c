/*****************************************************************************
*
*							Horner APG, LLC
*							Copyright (C) 2018
*							All rights reserved
*
******************************************************************************
*			C   M O D U L E   S P E C I F I C A T I O N   B L O C K
******************************************************************************
*
*	Module Name:	mqtt.c
*
*	Project:		APIs for MQTT.
*
*	Author:			
*
*	Description:	This file has application level APIs,Also it is used 
*	'libmosquiito.S0.1,libssl.so.1.1 and libcrypto.so.1.1'
*
*	Portability:	
*
******************************************************************************
*
*	Public
*	Functions:		mqttLibInit()
*					mqttLibDeinit()
*					mqttConnect()
*					mqttDisconnect()
*					mqttPublish()
*					mqttSubscribe()
*					mqttUnsubscribe()
*					
*
*	Public
*	Variables:		-
*
*	External
*	Functions:		-
*
*	External
*	Variables:		extern E_MQTT_STATES nextMqttState;
*					extern E_MQTT_EVENTS nextMqttEvent;
*
******************************************************************************
*
*	Revision History:
*
*	Date			Rev		By		Description of Revision
*
*	18-APR-2016		0.01	GAN		Initial development.
*
*	31-JUL-2016		0.02	GAN		Added Publish message count and 
*									Receive(Subscribe) message count.
******************************************************************************/

/************************/
/* System Include Files */
/************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
 
/*****************************/
/* Application Include Files */
/*****************************/
#include "mqtt.h"

extern E_MQTT_STATES nextMqttState;
extern E_MQTT_EVENTS nextMqttEvent;

INT mosqErrno;
CHAR pemPasswordBuf[128];
/* APIs */
/*****************************************************************************
*			C   F U N C T I O N   S P E C I F I C A T I O N   B L O C K
******************************************************************************
*
*	Function:		VOID mqttLibInit(VOID);
*
*	Call:			mqttLibInit()
*
*	Input(s):		-
*
*	Output(s):		-
*
*	Description:	This initialize pre requirements for MQTT library
*
*	Calls:			mosquitto_lib_init()
*
*****************************************************************************/
VOID mqttLibInit(VOID)
{
	mosquitto_lib_init();
}	// end of mqttLibInit()

/*****************************************************************************
*			C   F U N C T I O N   S P E C I F I C A T I O N   B L O C K
******************************************************************************
*
*	Function:		VOID mqttLibDeinit(VOID);
*
*	Call:			mqttLibDeinit()
*
*	Input(s):		-
*
*	Output(s):		-
*
*	Description:	This de-initialize pre requirements for MQTT library
*
*	Calls:			mosquitto_lib_cleanup()
*
*****************************************************************************/
VOID mqttLibDeinit(VOID)
{
	mosquitto_lib_cleanup();
}	// end of mqttLibDeinit()

/*****************************************************************************
*			C   F U N C T I O N   S P E C I F I C A T I O N   B L O C K
******************************************************************************
*
*	Function:		BOOL mqttConnect(MQTT_CONFIG *mqttConf);
*
*	Call:			mqttConnect(&mqttConf)
*
*	Input(s):		configuration instance
*
*	Output(s):		TRUE - SUCCESS or FALSE - FAILURE
*
*	Description:	This function will send CONNECT request and process the response.
*
*	Calls:			mosquitto_reconnect_async()
*					mosquitto_new()
*					mosquitto_username_pw_set()
*					mosquitto_connect_callback_set()
*					mosquitto_log_callback_set()
*					mosquitto_disconnect_callback_set()
*					mosquitto_tls_set()
*					mosquitto_tls_opts_set()
*					mosquitto_connect_async()
*					mosquitto_loop_start()
*
*****************************************************************************/
BOOL mqttConnect(MQTT_CONFIG *mqttConf)
{
	#if DEBUG
	printf("Create Broker Instance and Connect..%s:%s\n",mqttConf->mqttConnName,mqttConf->clientId);
	#endif

	if(mqttConf->clientStatus.isBrokerConnected)
	{
		mosqErrno = mosquitto_reconnect_async(mqttConf->mqttInst);
		if(mosqErrno != MOSQ_ERR_SUCCESS)
		{
			printf("Unable to reconnect to mqtt broker..%s:%s - %s\n",mqttConf->mqttConnName,
																	mqttConf->clientId,
																	mosquitto_strerror(mosqErrno));
			goto G_FLASE;
		}
		else
		{
			goto G_TRUE;
		}
	}
	/* New Mqtt Instance */
	mqttConf->mqttInst = mosquitto_new(mqttConf->clientId, mqttConf->cleanSession,(VOID *)mqttConf);
	if(!mqttConf->mqttInst)
	{
		printf("Error: Out of memory..%s:%s\n",mqttConf->mqttConnName,mqttConf->clientId);
		goto G_FLASE;
	}

	/* Set Username Password */
	if(mqttConf->mqttBrokerUname != NULL && mqttConf->mqttBrokerPasswd != NULL)
	{
		mosqErrno =  mosquitto_username_pw_set(	mqttConf->mqttInst,(const CHAR *)mqttConf->mqttBrokerUname,
																	(const CHAR *)mqttConf->mqttBrokerPasswd );
		if(mosqErrno != MOSQ_ERR_SUCCESS)
		{
			printf("Mqtt Broker Username and Password Set Error..%s:%s\n",mqttConf->mqttConnName,mqttConf->clientId);
			goto G_FLASE;
		}
	}
	
	mosquitto_connect_callback_set(mqttConf->mqttInst, connectCallback);
	mosquitto_log_callback_set(mqttConf->mqttInst, logCallback);
	mosquitto_disconnect_callback_set(mqttConf->mqttInst,disconnectCallback);

	/* Client Type */
	if(mqttConf->clientType == PUBLISHER)
	{
		mosquitto_publish_callback_set(mqttConf->mqttInst, publishCallback);
	}
	else if(mqttConf->clientType == SUBSCRIBER)
	{
		mosquitto_message_callback_set(mqttConf->mqttInst, messageCallback);
		mosquitto_subscribe_callback_set(mqttConf->mqttInst, subscribeCallback);
	}
	else
	{
		mosquitto_message_callback_set(mqttConf->mqttInst, messageCallback);
		mosquitto_subscribe_callback_set(mqttConf->mqttInst, subscribeCallback);
		mosquitto_publish_callback_set(mqttConf->mqttInst, publishCallback);
	}
	
	if(mqttConf->sslTlsConfig.withSsl)
	{
		if(mqttConf->sslTlsConfig.sslType == PRESHARED_KEY)
		{
			printf("Not Implemented..\n");
		}
		else
		{
			if(mqttConf->sslTlsConfig.caOnly) /*ADDED 1*/
			{
				mosqErrno = mosquitto_tls_set(mqttConf->mqttInst,
								(const CHAR *)mqttConf->sslTlsConfig.caCrtFile,NULL,NULL,NULL,NULL);
			}
			else
			{
				memset(pemPasswordBuf,0,sizeof(pemPasswordBuf));
				strcpy(pemPasswordBuf,mqttConf->sslTlsConfig.pemPassword);
				mosqErrno = mosquitto_tls_set(mqttConf->mqttInst,
											(const CHAR *)mqttConf->sslTlsConfig.caCrtFile,NULL,
											(const CHAR *)mqttConf->sslTlsConfig.clientCrtFile,
											(const CHAR *)mqttConf->sslTlsConfig.clientKeyFile,
											tlsPwdCallback);
			}//*ADDED 1*/
			
			if(mosqErrno != MOSQ_ERR_SUCCESS)
			{
				printf("Mqtt TLS set error..%s:%s\n",mqttConf->mqttConnName,mqttConf->clientId);
				goto G_FLASE;
			}

			mosqErrno = mosquitto_tls_opts_set(mqttConf->mqttInst,SSL_VERIFY_PEER,(const CHAR *)mqttConf->sslTlsConfig.tlsVersion,NULL);
			if(mosqErrno != MOSQ_ERR_SUCCESS)
			{
				printf("Mqtt TLS set options error..%s:%s\n",mqttConf->mqttConnName,mqttConf->clientId);
				goto G_FLASE;
			}
		}
	}

	/*ADDED 1*/
	if(mqttConf->sslTlsConfig.insecure)
	{
		mosqErrno = mosquitto_tls_insecure_set(	mqttConf->mqttInst,TRUE );
		if(mosqErrno != MOSQ_ERR_SUCCESS)
		{
			printf("Mqtt TLS set insecure error..%s:%s\n",mqttConf->mqttConnName,mqttConf->clientId);
			goto G_FLASE;
		}
	}//*ADDED 1*/

	/* Set max in-flight message count  */
	mosqErrno = mosquitto_max_inflight_messages_set(mqttConf->mqttInst, 24);
	if(mosqErrno != MOSQ_ERR_SUCCESS)
	{
		#if DEBUG
		printf("Mqtt set max in-flight messages error..%s:%s\n",mqttConf->mqttConnName,mqttConf->clientId);
		#endif
	}

	/* Connect to Broker */
	mosqErrno = mosquitto_connect_async(mqttConf->mqttInst, mqttConf->mqttBrokerIp, 
										mqttConf->mqttBrokerPort, mqttConf->keepAlive);
	if(mosqErrno != MOSQ_ERR_SUCCESS)
	{
		printf("Unable to connect to mqtt broker..%s:%s - %s\n",mqttConf->mqttConnName,
																mqttConf->clientId,
																mosquitto_strerror(mosqErrno));
		goto G_FLASE;
	}

	/* Create Mqtt Network Handle Thread */
	mosqErrno = mosquitto_loop_start(mqttConf->mqttInst);
	if ( mosqErrno != MOSQ_ERR_SUCCESS )
	{
		printf("Mqtt Loop thread start error..%s:%s\n",mqttConf->mqttConnName,mqttConf->clientId);
		goto G_FLASE;
	}

	G_TRUE:
	return TRUE;
	
	G_FLASE:
	mqttConf->clientStatus.isBrokerConnected = FALSE;
	return FALSE;
}	// end of mqttConnect()

/*****************************************************************************
*			C   F U N C T I O N   S P E C I F I C A T I O N   B L O C K
******************************************************************************
*
*	Function:		BOOL mqttDisconnect(MQTT_CONFIG *mqttConf);
*
*	Call:			mqttDisconnect(&mqttConf)
*
*	Input(s):		configuration instance
*
*	Output(s):		TRUE
*
*	Description:	It will disconnect the client from broker.
*
*	Calls:			mosquitto_disconnect()
*					mosquitto_loop_stop()
*					mosquitto_destroy()
*
*****************************************************************************/
BOOL mqttDisconnect(MQTT_CONFIG *mqttConf)
{
	INT32 i=0;
		
	mosquitto_disconnect(mqttConf->mqttInst);
	mosquitto_loop_stop(mqttConf->mqttInst,TRUE);
	if( mqttConf->clientStatus.isBrokerConnected == TRUE)
		mosquitto_destroy(mqttConf->mqttInst);
	
	if(mqttConf->cleanSession)
	{
		for(i=0;i < mqttConf->totalSubCount;i++)
		{
			mqttConf->subMqttMsg[i].msgStatus.subscribeDataStatus = FALSE;
		}
	}
	
	return TRUE;
}	// end of mqttDisconnect()

/*****************************************************************************
*			C   F U N C T I O N   S P E C I F I C A T I O N   B L O C K
******************************************************************************
*
*	Function:		BOOL mqttPublish(MQTT_CONFIG *mqttConf,UINT32 pubMsgIndex);
*
*	Call:			mqttPublish(&mqttConf,index)
*
*	Input(s):		configuration instance and publish index
*
*	Output(s):		TRUE - SUCCESS or FALSE - FAILURE
*
*	Description:	It will PUBLISH(send) the message to Broker
*
*	Calls:			mosquitto_publish()
*
*****************************************************************************/
BOOL mqttPublish(MQTT_CONFIG *mqttConf,UINT32 pubMsgIndex)
{
	#if DEBUG
	printf("Pub Toipic: %s\n",mqttConf->pubMqttMsg[pubMsgIndex].topic);
	#endif
	mosqErrno = mosquitto_publish(	mqttConf->mqttInst,
									&mqttConf->pubMqttMsg[pubMsgIndex].msgId,
									(const CHAR *)mqttConf->pubMqttMsg[pubMsgIndex].topic,
									mqttConf->pubMqttMsg[pubMsgIndex].msgLen,
									(const VOID *)mqttConf->pubMqttMsg[pubMsgIndex].msg,
									mqttConf->pubMqttMsg[pubMsgIndex].qos,
									(bool)mqttConf->pubMqttMsg[pubMsgIndex].retain );

	free((VOID *)mqttConf->pubMqttMsg[pubMsgIndex].msg); // release json memory
	mqttConf->pubMqttMsg[pubMsgIndex].msg = NULL;
									
	if( mosqErrno != MOSQ_ERR_SUCCESS )
	{
		printf("mosquitto_publish() : Failed..Retry at next state..%s:%s - %s\n",mqttConf->mqttConnName,
																				 mqttConf->clientId,
																				 mosquitto_strerror(mosqErrno));
		//mqttConf->pubMqttMsg[pubMsgIndex].retryCnt++;
		return FALSE;
	}
	else
	{
		if(mqttConf->pubMqttMsg[pubMsgIndex].qos)
			mqttConf->pubMqttMsg[pubMsgIndex].sending = TRUE;
	}
	mqttConf->totalPubMsgCount++; /*v0.02*/
	return TRUE;
}	// end of mqttPublish()

/*****************************************************************************
*			C   F U N C T I O N   S P E C I F I C A T I O N   B L O C K
******************************************************************************
*
*	Function:		BOOL mqttSubscribe(MQTT_CONFIG *mqttConf,UINT32 subMsgIndex);
*
*	Call:			mqttSubscribe(&mqttConf,index)
*
*	Input(s):		configuration instance and Subscribe index
*
*	Output(s):		TRUE - SUCCESS or FALSE - FAILURE
*
*	Description:	This function will subscribe the topic in broker
*					It won't receive any message
*
*	Calls:			mosquitto_subscribe()
*
*****************************************************************************/
BOOL mqttSubscribe(MQTT_CONFIG *mqttConf,UINT32 subMsgIndex)
{
	#if DEBUG
	printf("Sub Toipic: %s\n",mqttConf->subMqttMsg[subMsgIndex].topic);
	#endif

	mosqErrno = mosquitto_subscribe(mqttConf->mqttInst,
									&mqttConf->subMqttMsg[subMsgIndex].msgId,
									mqttConf->subMqttMsg[subMsgIndex].topic,
									mqttConf->subMqttMsg[subMsgIndex].qos);
	if( mosqErrno != MOSQ_ERR_SUCCESS )
	{
		printf("mqttSubscribe() : Failed..Try to subscribe next state..%s\n",mosquitto_strerror(mosqErrno));
		//mqttConf->subMqttMsg[subMsgIndex].retryCnt++;
		return FALSE;
	}
	else
		mqttConf->subMqttMsg[subMsgIndex].msgStatus.subscribeCmdSent = TRUE;

	return TRUE;
}	// end of mqttSubscribe()

/*****************************************************************************
*			C   F U N C T I O N   S P E C I F I C A T I O N   B L O C K
******************************************************************************
*
*	Function:		BOOL mqttUnsubscribe(MQTT_CONFIG *mqttConf,UINT32 subMsgIndex);
*
*	Call:			mqttUnsubscribe(&mqttConf,index)
*
*	Input(s):		configuration instance and unsubscribe index
*
*	Output(s):		TRUE - SUCCESS or FALSE - FAILURE
*
*	Description:	This function will unsubscribe the topic in broker
*
*	Calls:			mosquitto_unsubscribe()
*
*****************************************************************************/
BOOL mqttUnsubscribe(MQTT_CONFIG *mqttConf,UINT32 subMsgIndex)
{
	mosqErrno = mosquitto_unsubscribe(mqttConf->mqttInst,
									  &mqttConf->subMqttMsg[subMsgIndex].msgId,
									  mqttConf->subMqttMsg[subMsgIndex].topic);
	if( mosqErrno != MOSQ_ERR_SUCCESS )
	{
		printf("mqttUnsubscribe() : unsubscribe failed..%s\n",mosquitto_strerror(mosqErrno));
		//setErrStatus();
		return FALSE;
	}
	return TRUE;
}	// end of mqttUnsubscribe()

/*****************************************************************************
*			C   F U N C T I O N   S P E C I F I C A T I O N   B L O C K
******************************************************************************
*
*	Function:		VOID connectCallback(struct mosquitto *mosq, VOID *userdata, INT result);
*
*	Call:			callback
*
*	Input(s):		mosquitto instance,userdata and result
*
*	Output(s):		-
*
*	Description:	If connection established between client and broker this callback will occur
*
*	Calls:			-
*
*****************************************************************************/
VOID connectCallback(struct mosquitto *mosq, VOID *userdata, INT result)
{
	MQTT_CONFIG *udata = (MQTT_CONFIG *)userdata;
	if(!result)
	{
		/* Subscribe to broker information topics on successful connect. */
		#if 1
		printf("Broker Connect Success %s:%ld\n",udata->mqttBrokerIp,udata->mqttBrokerPort);
		#endif
		udata->clientStatus.isBrokerConnected = TRUE;
	}
	else
	{
		printf("Connect failed.. Returncode %d - %s:%ld\n",result,udata->mqttBrokerIp,udata->mqttBrokerPort);
		udata->clientStatus.isBrokerConnected = FALSE;
	}
}	// end of connectCallback()

/*****************************************************************************
*			C   F U N C T I O N   S P E C I F I C A T I O N   B L O C K
******************************************************************************
*
*	Function:		VOID subscribeCallback(struct mosquitto *mosq, VOID *userdata, INT mid, INT qosCount, const INT *grantedQos);
*
*	Call:			callback
*
*	Input(s):		mosquitto instance,userdata,message id, QOS count and granted Qos
*
*	Output(s):		-
*
*	Description:	This callback will occur whenever subscription get success
*
*	Calls:			-
*
*****************************************************************************/
VOID subscribeCallback(struct mosquitto *mosq, VOID *userdata, INT mid, INT qosCount, const INT *grantedQos)
{
	MQTT_CONFIG *udata = (MQTT_CONFIG *)userdata;
	INT32 i = 0;
	#if DEBUG
	printf("Subscribed (mid: %d): %d",mid, grantedQos[0]);
	for(i=1; i<qosCount; i++)
	{
		printf(", %d", grantedQos[i]);
	}
	printf("\n");
	#endif
	for(i=0;i < udata->totalSubCount;i++)
	{
		if( mid == udata->subMqttMsg[i].msgId )
		{
			udata->subMqttMsg[i].msgStatus.subscribeDataStatus = TRUE;
			udata->subMqttMsg[i].msgStatus.subscribeCmdSent = FALSE;
			break;
		}
	}
}	// end of subscribeCallback()

/*****************************************************************************
*			C   F U N C T I O N   S P E C I F I C A T I O N   B L O C K
******************************************************************************
*
*	Function:		VOID messageCallback(struct mosquitto *mosq, VOID *userdata, const struct mosquitto_message *message);
*
*	Call:			callback
*
*	Input(s):		mosquitto instance,userdata,message instance
*
*	Output(s):		-
*
*	Description:	This callback will whenever message received from in subscribed topics.
*
*	Calls:			mosquitto_message_copy()
*
*****************************************************************************/
VOID messageCallback(struct mosquitto *mosq, VOID *userdata, const struct mosquitto_message *message)
{
	size_t len = 0;
	INT32 i=0;
	MQTT_CONFIG *udata = (MQTT_CONFIG *)userdata;
	if(message->payloadlen)
	{
		#if DEBUG
		printf("Topic:%s \nMsg Length:%d\n", message->topic,message->payloadlen);
		printf("Msg received:%s\n",(CHAR *)message->payload);
		#endif
		for(i=0;i < udata->totalSubCount;i++)
		{
			if(!strcmp(message->topic,udata->subMqttMsg[i].topic))
			{
				if( mosquitto_message_copy(&udata->subMqttMsg[i].mqttMessage,message) != MOSQ_ERR_SUCCESS)
				{
					printf("Message copy error..\n");
				}
				else
				{
					len = strlen(udata->subMqttMsg[i].mqttMessage.topic);
					udata->subMqttMsg[i].mqttMessage.topic[len] = '\0';
					udata->subMqttMsg[i].dataLoaded = TRUE;
					break;
				}
			}
		}
	}
	else
	{
		printf("Empty Msg:%s \n", message->topic);
	}
}	// end of messageCallback()

/*****************************************************************************
*			C   F U N C T I O N   S P E C I F I C A T I O N   B L O C K
******************************************************************************
*
*	Function:		VOID publishCallback(struct mosquitto *mosq, VOID *userdata, INT mid);
*
*	Call:			callback
*
*	Input(s):		list of formal and informal parameters to function
*						Descriptions of use
*
*	Output(s):		mosquitto instance,userdata,message id
*
*	Description:	This callback will whenever the publish get success.
*
*	Calls:			-
*
*****************************************************************************/
VOID publishCallback(struct mosquitto *mosq, VOID *userdata, INT mid)
{
	INT32 i=0;
	MQTT_CONFIG *udata = (MQTT_CONFIG *)userdata;
	
	#if DEBUG
	printf("Publish success mid : %d\n",mid);
	#endif
	for(i=0;i < udata->totalPubCount;i++)
	{
		if( mid == udata->pubMqttMsg[i].msgId )
		{
			udata->pubMqttMsg[i].dataLoaded = FALSE;
			udata->pubMqttMsg[i].sending = FALSE;
		}
	}
}	// end of publishCallback()

/*****************************************************************************
*			C   F U N C T I O N   S P E C I F I C A T I O N   B L O C K
******************************************************************************
*
*	Function:		VOID logCallback(struct mosquitto *mosq, VOID *userdata, INT level, const CHAR *str);
*
*	Call:			callback
*
*	Input(s):		-
*
*	Output(s):		-
*
*	Description:	This callback will whenever the library gives log messages.
*
*	Calls:			-
*
*****************************************************************************/
VOID logCallback(struct mosquitto *mosq, VOID *userdata, INT level, const CHAR *str)
{
	/* Pring all log messages regardless of level,and maintaining connection b/w publisher and broker */
	#if DEBUG
	printf("LOG: %s\n", str);
	#endif
}	// end of logCallback()

/*****************************************************************************
*			C   F U N C T I O N   S P E C I F I C A T I O N   B L O C K
******************************************************************************
*
*	Function:		VOID disconnectCallback(struct mosquitto *mosq, VOID *userdata, INT reasonCode);
*
*	Call:			callback
*
*	Input(s):		mosquitto instance,userdata and reason Code
*
*	Output(s):		-
*
*	Description:	If connection broken between client and broker this callback will occur
*
*	Calls:			-
*
*****************************************************************************/
VOID disconnectCallback(struct mosquitto *mosq, VOID *userdata, INT reasonCode)
{
	INT i=0;
	MQTT_CONFIG *udata = (MQTT_CONFIG *)userdata;
	#if DEBUG
	printf("Broker Disconnected..reasonCode : %d\n",reasonCode);
	#endif
	if(udata->cleanSession)
	{
		for(i=0;i < udata->totalSubCount;i++)
		{
			udata->subMqttMsg[i].msgStatus.subscribeDataStatus = FALSE;
		}
	}
	//udata->clientStatus.isBrokerConnected = FALSE;
}	// end of disconnectCallback()

/*****************************************************************************
*			C   F U N C T I O N   S P E C I F I C A T I O N   B L O C K
******************************************************************************
*
*	Function:		INT tlsPwdCallback(CHAR *buf, INT size, INT rwflag, VOID *userdata);
*
*	Call:			This callback function
*
*	Input(s):		Password buffer, its size and userData(mqtt instance).
*
*	Output(s):		Size PEM file password
*
*	Description:	This function will callback when decrypt the client key file 
*					to get the pem password.
*
*	Calls:			strlen()
*****************************************************************************/
INT tlsPwdCallback(CHAR *buf, INT size, INT rwflag, VOID *userdata)
{
	INT length = 0;
	
	if(!buf)
		return 0;
	
	length = strlen((const char *)pemPasswordBuf);

	memset(buf, 0, size);
	if(length+1 >= size)
	{
		strncpy(buf,pemPasswordBuf,size);
		return size;
	}
	else
	{
		strncpy(buf,pemPasswordBuf,length+1);
		return length;
	}

}	// end of tlsPwdCallback()

/* EOF */
