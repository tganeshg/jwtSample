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
#include <fcntl.h>
/*****************************/
/* Application Include Files */
/*****************************/
#include "mqtt.h"

E_MQTT_STATES			nextMqttState = STATE_GET_CONFIG;
E_MQTT_EVENTS			nextMqttEvent;
MQTT_CONFIG				mqttConf;

#if GOOGLE
GOOGLE_IOT_CONFIG		googleIotConf;
#endif

#if ATNT
ATNT_IOT_CONFIG			attIotConf;
#endif

extern INT 				errno;

#if GOOGLE
/**
 * Calculates issued at / expiration times for JWT and places the time, as a
 * Unix timestamp, in the strings passed to the function. The timeSize
 * parameter specifies the length of the string allocated for both iat and exp.
 */
static VOID getIatExp(GOOGLE_IOT_CONFIG *gIotConf,INT timeSize) 
{
	gIotConf->jwtInfos.iatTimeInsec = time(NULL);
	snprintf(gIotConf->jwtInfos.iat, timeSize, "%lu", gIotConf->jwtInfos.iatTimeInsec);
	snprintf(gIotConf->jwtInfos.exp, timeSize, "%lu", gIotConf->jwtInfos.iatTimeInsec + gIotConf->jwtInfos.expTime);
	return;
}

/**
 * Calculates a JSON Web Token (JWT) given the path to a EC private key and
 * Google Cloud project ID. Returns the JWT as a string.
 */
static BOOL createJwt(GOOGLE_IOT_CONFIG *gIotConf) 
{
	UINT32 timeSizes = sizeof(time_t) * 3 + 2;
	UINT8 *key = NULL; // Stores the Base64 encoded certificate
	size_t keyLen = 0;
	jwt_t *jwt = NULL;

	// Read private key from file
	FILE *fp = fopen(gIotConf->jwtInfos.privateKeyPath, "r");
	if(fp == (VOID *)NULL) 
	{
		printf("Could not open file: %s\n", gIotConf->jwtInfos.privateKeyPath);
		return FALSE;
	}
	fseek(fp, 0L, SEEK_END);
	keyLen = ftell(fp);
	fseek(fp, 0L, SEEK_SET);
	key = malloc(sizeof(UINT8) * (keyLen + 1)); // certificate length + \0
	fread(key, 1, keyLen, fp);
	key[keyLen] = '\0';
	fclose(fp);
	
	// Get JWT parts
	if( (gIotConf->jwtInfos.iat != NULL) && (gIotConf->jwtInfos.exp != NULL) )
	{
		free(gIotConf->jwtInfos.iat);
		free(gIotConf->jwtInfos.exp);
	}
	
	gIotConf->jwtInfos.iat = calloc((size_t)timeSizes,sizeof(CHAR));
	gIotConf->jwtInfos.exp = calloc((size_t)timeSizes,sizeof(CHAR));
	if( (gIotConf->jwtInfos.iat != NULL) && (gIotConf->jwtInfos.exp != NULL) )
		getIatExp(gIotConf,timeSizes);
	else
	{
		printf("iat,exp memory alloc failed..\n");
		return FALSE;
	}

	if(jwt_new(&jwt))
	{
		printf("jwt new Error : %s\n",strerror(errno));
		return FALSE;
	}

	// Write JWT
	if(jwt_add_grant(jwt, "iat", gIotConf->jwtInfos.iat)) 
	{
		printf("Error setting issue timestamp: %s\n",strerror(errno));
		return FALSE;
	}

	if(jwt_add_grant(jwt, "exp", gIotConf->jwtInfos.exp))
	{
		printf("Error setting expiration: %s\n",strerror(errno));
		return FALSE;
	}
	
	if(jwt_add_grant(jwt, "aud", gIotConf->projectId))
	{
		printf("Error adding audience: %s\n",strerror(errno));
		return FALSE;
	}
	
	if(jwt_set_alg(jwt, gIotConf->jwtInfos.jwtAlgType, key, keyLen)) 
	{
		printf("Error during set alg: %s\n",strerror(errno));
		return FALSE;
	}
	
	if(gIotConf->jwtInfos.jwtOutput != NULL)
		free(gIotConf->jwtInfos.jwtOutput);
	
	gIotConf->jwtInfos.jwtOutput = jwt_encode_str(jwt);
	if(gIotConf->jwtInfos.jwtOutput == NULL)
	{
		printf("jwt encode string error: %s\n",strerror(errno));
		return FALSE;
	}

	jwt_free(jwt);
	free(key);
	return TRUE;
}

#endif

// the random function
static VOID randNumberGen(const INT nMin, const INT nMax,INT *nRandonNumber)
{
	*nRandonNumber = 0;
	*nRandonNumber = rand()%(nMax-nMin) + nMin;
	return;
}

static VOID *stringCopy(VOID *des,const VOID *src,size_t size)
{
	if(des != NULL)
		free(des);
	
	des = calloc((size_t)(size+1),sizeof(CHAR));
	if(des != NULL)
		memcpy(des,src,size);
	else
	{
		printf("Couldn't alloc Memory..\n");
		//setMqttStatusReg();
		return NULL;
	}
	return des;
}

static CHAR *stringAppend(CHAR *des,const CHAR *src,size_t length)
{
	size_t len = 0;
	
	if(des != NULL)
	{
		len = strlen((const CHAR *)des);
		/* Reallocating memory */
		des = (CHAR *) realloc(des, (len+length+1));
		if(des !=NULL)
			strcat(des,src);
		else
		{
			printf("Couldn't realloc Memory..\n");
			//setMqttStatusReg();
			return NULL;
		}
	}
	else
	{
		/* Initial memory allocation */
		des = (CHAR *)calloc((length+1),sizeof(CHAR));
		if(des !=NULL)
			strcat(des,src);
		else
		{
			printf("Couldn't calloc Memory..\n");
			//setMqttStatusReg();
			return NULL;
		}
	}
	return des;
}

static BOOL readConfig(VOID)
{
	INT i=0;
	
	#if GOOGLE
		googleIotConf.projectId = (CHAR *)stringCopy((VOID*)googleIotConf.projectId,
										(const VOID *)(GOOGLE_PROJECT_ID),(size_t)strlen(GOOGLE_PROJECT_ID));
		googleIotConf.regisId = (CHAR *)stringCopy((VOID*)googleIotConf.regisId,
										(const VOID *)(GOOGLE_REGIS_ID),(size_t)strlen(GOOGLE_REGIS_ID));
		googleIotConf.deviceID = (CHAR *)stringCopy((VOID*)googleIotConf.deviceID,
										(const VOID *)(GOOGLE_DEVICE_ID),(size_t)strlen(GOOGLE_DEVICE_ID));
		googleIotConf.region = (CHAR *)stringCopy((VOID*)googleIotConf.region,
										(const VOID *)(GOOGLE_REGION),(size_t)strlen(GOOGLE_REGION));
		googleIotConf.jwtInfos.privateKeyPath = (CHAR *)stringCopy((VOID*)googleIotConf.jwtInfos.privateKeyPath,
										(const VOID *)(BROKER_CLCRT_FILE_NAME),(size_t)strlen(BROKER_CLCRT_FILE_NAME));
		googleIotConf.jwtInfos.jwtAlgType = GOOGLE_ALG_TYPE;
		googleIotConf.jwtInfos.expTime = (GOOGLE_JWT_EXP_TIME < 600 ) ? 600 : GOOGLE_JWT_EXP_TIME;
	#elif ATNT
		attIotConf.deviceName = (CHAR *)stringCopy((VOID*)attIotConf.deviceName,
										(const VOID *)(ATNT_DEVICE_NAME),(size_t)strlen(ATNT_DEVICE_NAME));
		attIotConf.deviceID = (CHAR *)stringCopy((VOID*)attIotConf.deviceID,
										(const VOID *)(ATNT_DEVICE_ID),(size_t)strlen(ATNT_DEVICE_ID));
		attIotConf.primaryEndPoint = (CHAR *)stringCopy((VOID*)attIotConf.primaryEndPoint,
										(const VOID *)(ATNT_PRIMARY_ENDPOINT),(size_t)strlen(ATNT_PRIMARY_ENDPOINT));
		attIotConf.primaryApiKey = (CHAR *)stringCopy((VOID*)attIotConf.primaryApiKey,
										(const VOID *)(ATNT_PRIMARY_API_KEY),(size_t)strlen(ATNT_PRIMARY_API_KEY));		
		attIotConf.streamID = (CHAR *)stringCopy((VOID*)attIotConf.streamID,
										(const VOID *)(ATNT_STREAMID),(size_t)strlen(ATNT_STREAMID));
	#endif
	
	/* MQTT Broker Ip */
	mqttConf.mqttBrokerIp = (CHAR *)calloc((size_t)strlen(BROKER_HOST)+1,sizeof(CHAR));
	strcpy(mqttConf.mqttBrokerIp,BROKER_HOST);
	
	/* Broker Port */
	mqttConf.mqttBrokerPort = BROKER_PORT;
	/* Other Info for Broker Connection */
	mqttConf.cleanSession = (UINT8)BROKER_CLEAN_SESSION;
	mqttConf.keepAlive = (INT)BROKER_KEEP_ALIVE;
	mqttConf.clientType = (UINT8)BROKER_CLIENT_TYPE;

	/* Username */
	if(strlen(BROKER_UNAME) > 0)
	{
		mqttConf.mqttBrokerUname = (CHAR *)stringCopy((VOID*)mqttConf.mqttBrokerUname,
															(const VOID *)(BROKER_UNAME),
															(size_t)strlen(BROKER_UNAME));
	}
	else
		mqttConf.mqttBrokerUname = "";

	/* Password */
	#if GOOGLE
		createJwt(&googleIotConf);
		if(strlen(googleIotConf.jwtInfos.jwtOutput) > 0)
		{
			mqttConf.mqttBrokerPasswd = (CHAR *)stringCopy((VOID*)mqttConf.mqttBrokerPasswd,
												(const VOID *)(googleIotConf.jwtInfos.jwtOutput),
												(size_t)strlen(googleIotConf.jwtInfos.jwtOutput));
		}
		else
			mqttConf.mqttBrokerPasswd = "";
	#else
		if(strlen(BROKER_PASSWD) > 0)
		{
			mqttConf.mqttBrokerPasswd = (CHAR *)stringCopy((VOID*)mqttConf.mqttBrokerPasswd,
														(const VOID *)(BROKER_PASSWD),
														(size_t)strlen(BROKER_PASSWD));
		}
		else
			mqttConf.mqttBrokerPasswd = "";
	#endif
	
	/* Client Id */ 
	#if GOOGLE
		mqttConf.clientId = stringAppend((CHAR *)mqttConf.clientId,(const CHAR *)KW_PROJID,strlen(KW_PROJID));
		mqttConf.clientId = stringAppend((CHAR *)mqttConf.clientId,(const CHAR *)googleIotConf.projectId,strlen(googleIotConf.projectId));
		mqttConf.clientId = stringAppend((CHAR *)mqttConf.clientId,(const CHAR *)KW_LOC,strlen(KW_LOC));
		mqttConf.clientId = stringAppend((CHAR *)mqttConf.clientId,(const CHAR *)googleIotConf.region,strlen(googleIotConf.region));
		mqttConf.clientId = stringAppend((CHAR *)mqttConf.clientId,(const CHAR *)KW_REGIS,strlen(KW_REGIS));
		mqttConf.clientId = stringAppend((CHAR *)mqttConf.clientId,(const CHAR *)googleIotConf.regisId,strlen(googleIotConf.regisId));
		mqttConf.clientId = stringAppend((CHAR *)mqttConf.clientId,(const CHAR *)KW_DEV,strlen(KW_DEV));
		mqttConf.clientId = stringAppend((CHAR *)mqttConf.clientId,(const CHAR *)googleIotConf.deviceID,strlen(googleIotConf.deviceID));
		//printf("G ClientID : %s\n",mqttConf.clientId);
	#else
		if(strlen(BROKER_CLIENT_ID) > 0)
		{
			mqttConf.clientId = (CHAR *)stringCopy((VOID*)mqttConf.clientId,
												(const VOID *)(BROKER_CLIENT_ID),
												(size_t)strlen(BROKER_CLIENT_ID));
		}
		else
		{
			mqttConf.clientId ="\0";
			mqttConf.cleanSession = TRUE;
		}
	#endif
	/* Connection Name */
	mqttConf.mqttConnName = "BrokerConnection";
	
	/* Corresponding Broker Connection enable/disable */
	mqttConf.enable = TRUE;
	
	/* Select with or without TLS/SSL */
	mqttConf.sslTlsConfig.withSsl = BROKER_SSL_ENABLE;
	
	/* Select TLs Version */
	mqttConf.sslTlsConfig.tlsVersion = BROKER_TLSV_1_2;

	/* SSL Type */
	mqttConf.sslTlsConfig.sslType = CERT_KEY; //Now its will support only with certificates

	/* ca files */
	mqttConf.sslTlsConfig.caOnly = CA_ONLY;
	if(mqttConf.sslTlsConfig.caOnly)
	{
		mqttConf.sslTlsConfig.caCrtFile = BROKER_CACRT_FILE_NAME;
	}
	else
	{
		mqttConf.sslTlsConfig.caCrtFile = BROKER_CACRT_FILE_NAME;
		mqttConf.sslTlsConfig.clientCrtFile = BROKER_CLCRT_FILE_NAME;
		mqttConf.sslTlsConfig.clientKeyFile = BROKER_CLKEY_FILE_NAME;
		mqttConf.sslTlsConfig.pemPassword = (CHAR *)stringCopy((VOID*)mqttConf.sslTlsConfig.pemPassword,
																	(const VOID *)(BROKER_CLKEY_PASSWD),
																	(size_t)strlen(BROKER_CLKEY_PASSWD));
	}

	/* Subscribe  */
 	mqttConf.totalSubCount = BROKER_SUB_COUNT;
	for(i=0;i<mqttConf.totalSubCount;i++)
	{
		if(strlen(BROKER_SUB_TOPIC) > 0)
		{
			mqttConf.subMqttMsg[i].topic = (CHAR *)stringCopy((VOID*)mqttConf.subMqttMsg[i].topic,
								(const VOID *)(BROKER_SUB_TOPIC),
								(size_t)strlen(BROKER_SUB_TOPIC));
		}

		mqttConf.subMqttMsg[i].qos = (INT)BROKER_SUB_QOS;
		//mqttConf.subMqttMsg[i].msgId = (i+1);
	}
	
	/* Publish */
	mqttConf.totalPubCount = BROKER_PUB_COUNT;
	for(i=0;i<mqttConf.totalPubCount;i++)
	{
		#if GOOGLE
		mqttConf.pubMqttMsg[i].topic = stringAppend((CHAR *)mqttConf.pubMqttMsg[i].topic,(const CHAR *)KW_DEV,strlen(KW_DEV));
		mqttConf.pubMqttMsg[i].topic = stringAppend((CHAR *)mqttConf.pubMqttMsg[i].topic,(const CHAR *)googleIotConf.deviceID,strlen(googleIotConf.deviceID));
		mqttConf.pubMqttMsg[i].topic = stringAppend((CHAR *)mqttConf.pubMqttMsg[i].topic,(const CHAR *)KW_EVENT,strlen(KW_EVENT));
		#elif ATNT
		mqttConf.pubMqttMsg[i].topic = stringAppend((CHAR *)mqttConf.pubMqttMsg[i].topic,(const CHAR *)KW_M2X,strlen(KW_M2X));
		mqttConf.pubMqttMsg[i].topic = stringAppend((CHAR *)mqttConf.pubMqttMsg[i].topic,(const CHAR *)attIotConf.primaryApiKey,strlen(attIotConf.primaryApiKey));
		mqttConf.pubMqttMsg[i].topic = stringAppend((CHAR *)mqttConf.pubMqttMsg[i].topic,(const CHAR *)KW_REQUESTS,strlen(KW_REQUESTS));
		#else
		mqttConf.pubMqttMsg[i].topic = (CHAR *)stringCopy((VOID*)mqttConf.pubMqttMsg[i].topic,
								(const VOID *)(BROKER_PUB_TOPIC),(size_t)strlen(BROKER_PUB_TOPIC));
		#endif
		mqttConf.pubMqttMsg[i].qos = (INT)BROKER_PUB_QOS;
		mqttConf.pubMqttMsg[i].retain = (BROKER_PUB_RETAINED)?TRUE:FALSE;

		mqttConf.pubMqttMsg[i].publishType = 1; /*Periodic only*/
		mqttConf.pubMqttMsg[i].perInterval = BROKER_PUB_PERIODIC_TIME;
		/* Data will be taken from random generator */
	}

	return TRUE;
}

static BOOL checkTimeout(UINT32 *timeTick,UINT32 timeout)
{
	/* If timeout is 0, start the timer. */
	if (timeout == 0)
		/* *timeTick = FPGA_GET_FRT_UINT32; */
		*timeTick = time(NULL);

	/* Return TRUE if the timer has expired. */
	/* return ( ((UINT32)(FPGA_GET_FRT_UINT32 - *timeTick)) >= timeout ); */
	return ( ((UINT32)(time(NULL) - *timeTick)) >= timeout );
}

VOID getValueAndConsJson(MQTT_CONFIG *mqttConf,UINT32 pubIndex)
{
	CHAR tempBuff[512];
	struct tm *timeptr;
	time_t temp;
	INT value = 0;

	randNumberGen(1,100,&value);
	temp = time(NULL);                                                            
	timeptr = localtime(&temp);
	
	#if ATNT
	mqttConf->pubMqttMsg[pubIndex].msg = stringAppend((CHAR *)mqttConf->pubMqttMsg[pubIndex].msg,(const CHAR *)"{",1);
	
	memset(tempBuff,0,sizeof(tempBuff));
	sprintf(tempBuff,"\"id\":\"%ld\",",attIotConf.msgIdCnt++);
	mqttConf->pubMqttMsg[pubIndex].msg = stringAppend((CHAR *)mqttConf->pubMqttMsg[pubIndex].msg,(const CHAR *)tempBuff,strlen(tempBuff));

	memset(tempBuff,0,sizeof(tempBuff));
	sprintf(tempBuff,"\"method\":\"POST\",");
	mqttConf->pubMqttMsg[pubIndex].msg = stringAppend((CHAR *)mqttConf->pubMqttMsg[pubIndex].msg,(const CHAR *)tempBuff,strlen(tempBuff));
																								 
	memset(tempBuff,0,sizeof(tempBuff));
	sprintf(tempBuff,"\"resource\":\"/v2%s/streams/%s/values\",",attIotConf.primaryEndPoint,attIotConf.streamID);
	mqttConf->pubMqttMsg[pubIndex].msg = stringAppend((CHAR *)mqttConf->pubMqttMsg[pubIndex].msg,(const CHAR *)tempBuff,strlen(tempBuff));

	memset(tempBuff,0,sizeof(tempBuff));
	sprintf(tempBuff,"\"agent\":\"M2X-Demo-Client/0.0.1\",");
	mqttConf->pubMqttMsg[pubIndex].msg = stringAppend((CHAR *)mqttConf->pubMqttMsg[pubIndex].msg,(const CHAR *)tempBuff,strlen(tempBuff));
																								 
	memset(tempBuff,0,sizeof(tempBuff));
	sprintf(tempBuff,"\"body\":{");
	mqttConf->pubMqttMsg[pubIndex].msg = stringAppend((CHAR *)mqttConf->pubMqttMsg[pubIndex].msg,(const CHAR *)tempBuff,strlen(tempBuff));
																								 
	memset(tempBuff,0,sizeof(tempBuff));
	sprintf(tempBuff,"\"values\":[");
	mqttConf->pubMqttMsg[pubIndex].msg = stringAppend((CHAR *)mqttConf->pubMqttMsg[pubIndex].msg,(const CHAR *)tempBuff,strlen(tempBuff));

	temp = time(NULL);                                                            
	timeptr = gmtime(&temp);
	memset(tempBuff,0,sizeof(tempBuff));
	strftime(tempBuff,sizeof(tempBuff)-1,"{\"timestamp\":\"%FT%I:%M:%S.000Z\",", timeptr); 
	mqttConf->pubMqttMsg[pubIndex].msg = stringAppend((CHAR *)mqttConf->pubMqttMsg[pubIndex].msg,(const CHAR *)tempBuff,strlen(tempBuff));
									
	memset(tempBuff,0,sizeof(tempBuff));
	sprintf(tempBuff,"\"value\":%d}]}}",value);
	mqttConf->pubMqttMsg[pubIndex].msg = stringAppend((CHAR *)mqttConf->pubMqttMsg[pubIndex].msg,(const CHAR *)tempBuff,strlen(tempBuff));

	#elif ( GOOGLE || AWS || AZURE)
	memset(tempBuff,0,sizeof(tempBuff));
	//strftime(tempBuff,sizeof(tempBuff)-1,"{\"timestamp\":\"%FT%I:%M:%S.000Z\",", timeptr); 
	strftime(tempBuff,sizeof(tempBuff)-1,"{\"Time\":\"%FT%I:%M:%S.000Z\",", timeptr); 
	mqttConf->pubMqttMsg[pubIndex].msg = stringAppend((CHAR *)mqttConf->pubMqttMsg[pubIndex].msg,(const CHAR *)tempBuff,strlen(tempBuff));
	
	memset(tempBuff,0,sizeof(tempBuff));
	//sprintf(tempBuff,"\"value\":%d}",value); 
	sprintf(tempBuff,"\"Testvalue\":%d}",value); 
	mqttConf->pubMqttMsg[pubIndex].msg = stringAppend((CHAR *)mqttConf->pubMqttMsg[pubIndex].msg,(const CHAR *)tempBuff,strlen(tempBuff));
	#endif
	
	mqttConf->pubMqttMsg[pubIndex].msgLen = strlen((const CHAR *)mqttConf->pubMqttMsg[pubIndex].msg);
	mqttConf->pubMqttMsg[pubIndex].dataLoaded = TRUE;

	printf("Json :\n%s\n",(CHAR *)mqttConf->pubMqttMsg[pubIndex].msg);

	return;
}

#if GOOGLE
static BOOL updateGooglePasswd(GOOGLE_IOT_CONFIG *gIotConf,MQTT_CONFIG *mqttConf)
{
	createJwt(gIotConf);
	if(strlen(gIotConf->jwtInfos.jwtOutput) > 0)
	{
		mqttConf->mqttBrokerPasswd = (CHAR *)stringCopy((VOID*)mqttConf->mqttBrokerPasswd,
													(const VOID *)(gIotConf->jwtInfos.jwtOutput),
													(size_t)strlen(gIotConf->jwtInfos.jwtOutput));
	}
	else
		mqttConf->mqttBrokerPasswd = "";
	
	return TRUE;
}

#endif

INT main(VOID)
{
	INT32 index = 0;
	//UINT8 value = 0;
	#if GOOGLE
	time_t curSec = 0;
	#endif

	memset(&mqttConf,0,sizeof(MQTT_CONFIG));
	
	while(TRUE)
	{
		switch(nextMqttState)
		{
			case STATE_GET_CONFIG:
			{
				mqttConf.totalPubMsgCount = 0;
				mqttConf.totalSubMsgCount = 0;
				if(readConfig())
				{
					mqttConf.retryCnt = 0;
					SET_STATE(STATE_LIB_INIT);
				}
				else
				{
					#if DEBUG
						printf("Invalid Mqtt Configuration..\n");
					#endif
					if(mqttConf.retryCnt < MQTT_RETRY)
					{
						mqttConf.retryCnt++;
						SET_STATE(STATE_GET_CONFIG);
					}
					else
					{
						#if DEBUG
							printf("Mqtt read config retry end..\n");
						#endif
						mqttConf.retryCnt = 0;
						SET_ST_EV(STATE_IDLE,EVENT_EMPTY);
					}
				}
			}
			break;
			case STATE_LIB_INIT:
			{
				if(mqttConf.enable)
				{
					mqttLibInit();
					SET_STATE(STATE_CONNECT);
				}
				else
				{
					SET_ST_EV(STATE_IDLE,EVENT_EMPTY);
				}
			}
			break;
			case STATE_LIB_DEINIT:
			{
				mqttLibDeinit();
				SET_STATE(STATE_LIB_INIT);
			}
			break;
			case STATE_CONNECT:
			{
				if(!mqttConnect(&mqttConf))
				{
					SET_STATE(STATE_DISCONNECT);
				}
				else
				{
					checkTimeout(&mqttConf.conTickTime,0); //Start Time
					SET_ST_EV(STATE_IDLE,EVENT_CONNECT_SENT);
				}
			}
			break;
			case STATE_DISCONNECT:
			{
				mqttDisconnect(&mqttConf);
				checkTimeout(&mqttConf.disConTickTime,0); //Start Time
				SET_ST_EV(STATE_IDLE,EVENT_DISCONNECT_SENT);
			}
			break;
			case STATE_PUBLISH:
			{
				for(index=0;index<mqttConf.totalPubCount;index++)
				{
					if( mqttConf.pubMqttMsg[index].dataLoaded )
					{
						mqttPublish(&mqttConf,index);
					}
				}
				SET_ST_EV(STATE_IDLE,EVENT_EMPTY);
			}
			break;
			case STATE_SUBSCRIBE:
			{
				for(index=0;index<mqttConf.totalSubCount;index++)
				{
					if( !mqttConf.subMqttMsg[index].msgStatus.subscribeDataStatus &&
						!mqttConf.subMqttMsg[index].msgStatus.subscribeCmdSent )
					{
						//Subscribe
						if( mqttSubscribe(&mqttConf,index) )
							checkTimeout(&mqttConf.subMqttMsg[index].subTickTime,0); //Start Time
					}
				}
				SET_ST_EV(STATE_IDLE,EVENT_EMPTY);
			}
			break;
			case STATE_PROC_MSG:
			{
				//procMsgToReg(&mqttConf);
				SET_ST_EV(STATE_IDLE,EVENT_EMPTY);
			}
			break;
			default:
			{
				switch(nextMqttEvent)
				{
					case EVENT_CONNECT_SENT:
					{
						if(mqttConf.clientStatus.isBrokerConnected)
						{
							SET_STATE(STATE_SUBSCRIBE);
						}
						else
						{
							/* if( checkTimeout(&mqttConf.conTickTime,(US_1_MS*5000)) ) //5 sec */
							if( checkTimeout(&mqttConf.conTickTime,(10)) ) //10 sec
								SET_STATE(STATE_DISCONNECT);
								/* SET_STATE(STATE_CONNECT); */
							else
							{
								SET_ST_EV(STATE_IDLE,EVENT_CONNECT_SENT);
							}
						}
					}
					break;
					case EVENT_DISCONNECT_SENT:
					{
						/* if( checkTimeout(&mqttConf.disConTickTime,(US_1_MS*3000)) ) //5 sec */
						if( checkTimeout(&mqttConf.disConTickTime,(3)) )
						{
							nextMqttState = STATE_CONNECT;
							mqttConf.clientStatus.isBrokerConnected = FALSE;
						}
						else
						{
							SET_ST_EV(STATE_IDLE,EVENT_DISCONNECT_SENT);
						}
					}
					break;
					case EVENT_PUBLISH:
					{
						SET_STATE(STATE_PUBLISH);
					}
					break;
					case EVENT_SUBSCRIBE:
					{
						SET_STATE(STATE_SUBSCRIBE);
					}
					break;
					case EVENT_PROC_MSG:
					{
						SET_STATE(STATE_PROC_MSG);
					}
					break;
					default: //EVENT_EMPTY
					{
						if(mqttConf.clientStatus.isBrokerConnected)
						{
							/**	Check timeout or trigger to publish the data(json) **/
							if(mqttConf.clientType == PUBLISHER || mqttConf.clientType == PUB_SUB_BOTH )
							{
								for(index=0;index<mqttConf.totalPubCount;index++)
								{
									if( checkTimeout(&mqttConf.pubMqttMsg[index].perIntervalTime,
													  mqttConf.pubMqttMsg[index].perInterval) )
									{
										checkTimeout(&mqttConf.pubMqttMsg[index].perIntervalTime,0);
										//construct json with given reg details
										printf("\nTime to send Data..\n");
										getValueAndConsJson(&mqttConf,index);
										SET_STATE(STATE_PUBLISH);
									}
									
								}
							}
							
							#if GOOGLE
							/* Reconnect if JWT is expired */
							curSec = time(NULL);
							googleIotConf.jwtInfos.secsFromIssue = curSec - googleIotConf.jwtInfos.iatTimeInsec;
							if(googleIotConf.jwtInfos.secsFromIssue > (googleIotConf.jwtInfos.expTime - 15) ) /* before 15 sec reconnect */
							{
								printf("Token generated before %d \n",googleIotConf.jwtInfos.secsFromIssue);
								updateGooglePasswd(&googleIotConf,&mqttConf);
								printf("Config Updated....\n");
								SET_STATE(STATE_CONNECT);
							}
							#endif
						}
						#if GOOGLE
						else
						{
							updateGooglePasswd(&googleIotConf,&mqttConf);
							printf("Config Updated..\n");
							SET_STATE(STATE_DISCONNECT);
						}
						#endif
					}
					break;
				}
			}
			break;
		}
	}
	return 0;
}

/* EOF */