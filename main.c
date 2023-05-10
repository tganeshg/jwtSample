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
#include <sys/time.h>
/*****************************/
/* Application Include Files */
/*****************************/
#include "mqtt.h"

MQTT_CONFIG				mqttConf[MAX_BROKER_CONNECTION];
BOOL onetime = TRUE;

/* GOOGLE */
GOOGLE_IOT_CONFIG		googleIotConf;

/* ATNT */
ATNT_IOT_CONFIG			attIotConf;

extern INT 				errno;

/* Private */
static unsigned long long timeInMilliseconds(void) {
    struct timeval tv;

    gettimeofday(&tv,NULL);
    return (((unsigned long long)tv.tv_sec)*1000)+(tv.tv_usec/1000);
}
/* *********************************** */

/* GOOGLE */
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

static BOOL readConfig(INT32 idx)
{
	INT i=0;

	/* Common Info for Broker Connection */
	mqttConf[idx].cleanSession = (UINT8)BROKER_CLEAN_SESSION;
	mqttConf[idx].keepAlive = (INT)BROKER_KEEP_ALIVE;
	mqttConf[idx].clientType = (UINT8)BROKER_CLIENT_TYPE;

	switch(idx)
	{
		case IDX_HORNER:
		{
			/* Connection Name */
			mqttConf[idx].mqttConnName = "HORNER";
			
			/* Corresponding Broker Connection enable/disable */
			mqttConf[idx].enable = TRUE;

			/* MQTT Broker Ip */
			mqttConf[idx].mqttBrokerIp = (CHAR *)calloc((size_t)strlen(BROKER_HORNER_HOST)+1,sizeof(CHAR));
			strcpy(mqttConf[idx].mqttBrokerIp,BROKER_HORNER_HOST);
			
			/* Broker Port */
			mqttConf[idx].mqttBrokerPort = BROKER_HORNER_PORT;

			/* Username */
			if(strlen(BROKER_HORNER_UNAME) > 0)
			{
				mqttConf[idx].mqttBrokerUname = (CHAR *)stringCopy((VOID*)mqttConf[idx].mqttBrokerUname,
																	(const VOID *)(BROKER_HORNER_UNAME),
																	(size_t)strlen(BROKER_HORNER_UNAME));
			}
			else
				mqttConf[idx].mqttBrokerUname = "";

			/* Password */
			if(strlen(BROKER_HORNER_PASSWD) > 0)
			{
				mqttConf[idx].mqttBrokerPasswd = (CHAR *)stringCopy((VOID*)mqttConf[idx].mqttBrokerPasswd,
															(const VOID *)(BROKER_HORNER_PASSWD),
															(size_t)strlen(BROKER_HORNER_PASSWD));
			}
			else
				mqttConf[idx].mqttBrokerPasswd = "";

			/* Client Id */
			if(strlen(BROKER_HORNER_CLIENT_ID) > 0)
			{
				mqttConf[idx].clientId = (CHAR *)stringCopy((VOID*)mqttConf[idx].clientId,
													(const VOID *)(BROKER_HORNER_CLIENT_ID),
													(size_t)strlen(BROKER_HORNER_CLIENT_ID));
			}
			else
			{
				mqttConf[idx].clientId ="\0";
				mqttConf[idx].cleanSession = TRUE;
			}

			/* Select with or without TLS/SSL */
			mqttConf[idx].sslTlsConfig.withSsl = HORNER_BROKER_SSL_ENABLE;
			
			/* Select TLs Version */
			mqttConf[idx].sslTlsConfig.tlsVersion = BROKER_TLSV_1_2;

			/* SSL Type */
			mqttConf[idx].sslTlsConfig.sslType = CERT_KEY; //Now its will support only with certificates

			/* ca files */
			mqttConf[idx].sslTlsConfig.caOnly = HORNER_CA_ONLY;
			if(mqttConf[idx].sslTlsConfig.caOnly)
			{
				mqttConf[idx].sslTlsConfig.caCrtFile = HORNER_BROKER_CACRT_FILE_NAME;
			}
			else
			{
				mqttConf[idx].sslTlsConfig.caCrtFile = HORNER_BROKER_CACRT_FILE_NAME;
				mqttConf[idx].sslTlsConfig.clientCrtFile = HORNER_BROKER_CLCRT_FILE_NAME;
				mqttConf[idx].sslTlsConfig.clientKeyFile = HORNER_BROKER_CLKEY_FILE_NAME;
				mqttConf[idx].sslTlsConfig.pemPassword = (CHAR *)stringCopy((VOID*)mqttConf[idx].sslTlsConfig.pemPassword,
																			(const VOID *)(HORNER_BROKER_CLKEY_PASSWD),
																			(size_t)strlen(HORNER_BROKER_CLKEY_PASSWD));
			}

			/* Subscribe  */
			mqttConf[idx].totalSubCount = HP_BROKER_SUB_COUNT;
			for(i=0;i<mqttConf[idx].totalSubCount;i++)
			{
				if(strlen(HP_BROKER_SUB_TOPIC) > 0)
				{
					mqttConf[idx].subMqttMsg[i].topic = (CHAR *)stringCopy((VOID*)mqttConf[idx].subMqttMsg[i].topic,
																			(const VOID *)(HP_BROKER_SUB_TOPIC),
																			(size_t)strlen(HP_BROKER_SUB_TOPIC));
				}

				mqttConf[idx].subMqttMsg[i].qos = (INT)HP_BROKER_SUB_QOS;
				//mqttConf[idx].subMqttMsg[i].msgId = (i+1);
			}

			/* Publish */
			mqttConf[idx].totalPubCount = HP_BROKER_PUB_COUNT;
			for(i=0;i<mqttConf[idx].totalPubCount;i++)
			{
				mqttConf[idx].pubMqttMsg[i].topic = (CHAR *)stringCopy((VOID*)mqttConf[idx].pubMqttMsg[i].topic,
															(const VOID *)(HP_BROKER_PUB_TOPIC),(size_t)strlen(HP_BROKER_PUB_TOPIC));
				mqttConf[idx].pubMqttMsg[i].qos = (INT)HP_BROKER_PUB_QOS;
				mqttConf[idx].pubMqttMsg[i].retain = (HP_BROKER_PUB_RETAINED)?TRUE:FALSE;

				mqttConf[idx].pubMqttMsg[i].publishType = 1; /*Periodic only*/
				mqttConf[idx].pubMqttMsg[i].perInterval = HP_BROKER_PUB_PERIODIC_TIME;
				/* Data will be taken from random generator */
			}
		}
		break;
		case IDX_AWS:
		{
			/* Connection Name */
			mqttConf[idx].mqttConnName = "AWS";
			
			/* Corresponding Broker Connection enable/disable */
			mqttConf[idx].enable = TRUE;

			/* MQTT Broker Ip */
			mqttConf[idx].mqttBrokerIp = (CHAR *)calloc((size_t)strlen(BROKER_AWS_HOST)+1,sizeof(CHAR));
			strcpy(mqttConf[idx].mqttBrokerIp,BROKER_AWS_HOST);
			
			/* Broker Port */
			mqttConf[idx].mqttBrokerPort = BROKER_AWS_PORT;

			/* Username */
			if(strlen(BROKER_AWS_UNAME) > 0)
			{
				mqttConf[idx].mqttBrokerUname = (CHAR *)stringCopy((VOID*)mqttConf[idx].mqttBrokerUname,
																	(const VOID *)(BROKER_AWS_UNAME),
																	(size_t)strlen(BROKER_AWS_UNAME));
			}
			else
				mqttConf[idx].mqttBrokerUname = "";

			/* Password */
			if(strlen(BROKER_AWS_PASSWD) > 0)
			{
				mqttConf[idx].mqttBrokerPasswd = (CHAR *)stringCopy((VOID*)mqttConf[idx].mqttBrokerPasswd,
															(const VOID *)(BROKER_AWS_PASSWD),
															(size_t)strlen(BROKER_AWS_PASSWD));
			}
			else
				mqttConf[idx].mqttBrokerPasswd = "";

			/* Client Id */
			if(strlen(BROKER_AWS_CLIENT_ID) > 0)
			{
				mqttConf[idx].clientId = (CHAR *)stringCopy((VOID*)mqttConf[idx].clientId,
													(const VOID *)(BROKER_AWS_CLIENT_ID),
													(size_t)strlen(BROKER_AWS_CLIENT_ID));
			}
			else
			{
				mqttConf[idx].clientId ="\0";
				mqttConf[idx].cleanSession = TRUE;
			}

			/* Select with or without TLS/SSL */
			mqttConf[idx].sslTlsConfig.withSsl = AWS_BROKER_SSL_ENABLE;
			
			/* Select TLs Version */
			mqttConf[idx].sslTlsConfig.tlsVersion = BROKER_TLSV_1_2;

			/* SSL Type */
			mqttConf[idx].sslTlsConfig.sslType = CERT_KEY; //Now its will support only with certificates

			/* ca files */
			mqttConf[idx].sslTlsConfig.caOnly = AWS_CA_ONLY;
			if(mqttConf[idx].sslTlsConfig.caOnly)
			{
				mqttConf[idx].sslTlsConfig.caCrtFile = AWS_BROKER_CACRT_FILE_NAME;
			}
			else
			{
				mqttConf[idx].sslTlsConfig.caCrtFile = AWS_BROKER_CACRT_FILE_NAME;
				mqttConf[idx].sslTlsConfig.clientCrtFile = AWS_BROKER_CLCRT_FILE_NAME;
				mqttConf[idx].sslTlsConfig.clientKeyFile = AWS_BROKER_CLKEY_FILE_NAME;
				mqttConf[idx].sslTlsConfig.pemPassword = (CHAR *)stringCopy((VOID*)mqttConf[idx].sslTlsConfig.pemPassword,
																			(const VOID *)(AWS_BROKER_CLKEY_PASSWD),
																			(size_t)strlen(AWS_BROKER_CLKEY_PASSWD));
			}

			/* Subscribe  */
			mqttConf[idx].totalSubCount = AWS_BROKER_SUB_COUNT;
			for(i=0;i<mqttConf[idx].totalSubCount;i++)
			{
				if(strlen(AWS_BROKER_SUB_TOPIC) > 0)
				{
					mqttConf[idx].subMqttMsg[i].topic = (CHAR *)stringCopy((VOID*)mqttConf[idx].subMqttMsg[i].topic,
																			(const VOID *)(AWS_BROKER_SUB_TOPIC),
																			(size_t)strlen(AWS_BROKER_SUB_TOPIC));
				}

				mqttConf[idx].subMqttMsg[i].qos = (INT)AWS_BROKER_SUB_QOS;
				//mqttConf[idx].subMqttMsg[i].msgId = (i+1);
			}

			/* Publish */
			mqttConf[idx].totalPubCount = AWS_BROKER_PUB_COUNT;
			for(i=0;i<mqttConf[idx].totalPubCount;i++)
			{
				mqttConf[idx].pubMqttMsg[i].topic = (CHAR *)stringCopy((VOID*)mqttConf[idx].pubMqttMsg[i].topic,
															(const VOID *)(AWS_BROKER_PUB_TOPIC),(size_t)strlen(AWS_BROKER_PUB_TOPIC));
				mqttConf[idx].pubMqttMsg[i].qos = (INT)AWS_BROKER_PUB_QOS;
				mqttConf[idx].pubMqttMsg[i].retain = (AWS_BROKER_PUB_RETAINED)?TRUE:FALSE;

				mqttConf[idx].pubMqttMsg[i].publishType = 1; /*Periodic only*/
				mqttConf[idx].pubMqttMsg[i].perInterval = AWS_BROKER_PUB_PERIODIC_TIME;
				/* Data will be taken from random generator */
			}
		}
		break;
		case IDX_GOOGLE:
		{
			/* Connection Name */
			mqttConf[idx].mqttConnName = "GOOGLE";
			
			/* Corresponding Broker Connection enable/disable */
			mqttConf[idx].enable = TRUE;

			googleIotConf.projectId = (CHAR *)stringCopy((VOID*)googleIotConf.projectId,
											(const VOID *)(GOOGLE_PROJECT_ID),(size_t)strlen(GOOGLE_PROJECT_ID));
			googleIotConf.regisId = (CHAR *)stringCopy((VOID*)googleIotConf.regisId,
											(const VOID *)(GOOGLE_REGIS_ID),(size_t)strlen(GOOGLE_REGIS_ID));
			googleIotConf.deviceID = (CHAR *)stringCopy((VOID*)googleIotConf.deviceID,
											(const VOID *)(GOOGLE_DEVICE_ID),(size_t)strlen(GOOGLE_DEVICE_ID));
			googleIotConf.region = (CHAR *)stringCopy((VOID*)googleIotConf.region,
											(const VOID *)(GOOGLE_REGION),(size_t)strlen(GOOGLE_REGION));
			googleIotConf.jwtInfos.privateKeyPath = (CHAR *)stringCopy((VOID*)googleIotConf.jwtInfos.privateKeyPath,
											(const VOID *)(GOOGLE_BROKER_CLCRT_FILE_NAME),(size_t)strlen(GOOGLE_BROKER_CLCRT_FILE_NAME));
			googleIotConf.jwtInfos.jwtAlgType = GOOGLE_ALG_TYPE;
			googleIotConf.jwtInfos.expTime = (GOOGLE_JWT_EXP_TIME < 600 ) ? 600 : GOOGLE_JWT_EXP_TIME;
			
			/* MQTT Broker Ip */
			mqttConf[idx].mqttBrokerIp = (CHAR *)calloc((size_t)strlen(BROKER_GOOGLE_HOST)+1,sizeof(CHAR));
			strcpy(mqttConf[idx].mqttBrokerIp,BROKER_GOOGLE_HOST);
			
			/* Broker Port */
			mqttConf[idx].mqttBrokerPort = BROKER_GOOGLE_PORT;

			/* Username */
			if(strlen(BROKER_GOOGLE_UNAME) > 0)
			{
				mqttConf[idx].mqttBrokerUname = (CHAR *)stringCopy((VOID*)mqttConf[idx].mqttBrokerUname,
																	(const VOID *)(BROKER_GOOGLE_UNAME),
																	(size_t)strlen(BROKER_GOOGLE_UNAME));
			}
			else
				mqttConf[idx].mqttBrokerUname = "";
			
			/* Password */
			createJwt(&googleIotConf);
			if(strlen(googleIotConf.jwtInfos.jwtOutput) > 0)
			{
				mqttConf[idx].mqttBrokerPasswd = (CHAR *)stringCopy((VOID*)mqttConf[idx].mqttBrokerPasswd,
													(const VOID *)(googleIotConf.jwtInfos.jwtOutput),
													(size_t)strlen(googleIotConf.jwtInfos.jwtOutput));
			}
			else
				mqttConf[idx].mqttBrokerPasswd = "";

			/* Client Id */
			mqttConf[idx].clientId = stringAppend((CHAR *)mqttConf[idx].clientId,(const CHAR *)KW_PROJID,strlen(KW_PROJID));
			mqttConf[idx].clientId = stringAppend((CHAR *)mqttConf[idx].clientId,(const CHAR *)googleIotConf.projectId,strlen(googleIotConf.projectId));
			mqttConf[idx].clientId = stringAppend((CHAR *)mqttConf[idx].clientId,(const CHAR *)KW_LOC,strlen(KW_LOC));
			mqttConf[idx].clientId = stringAppend((CHAR *)mqttConf[idx].clientId,(const CHAR *)googleIotConf.region,strlen(googleIotConf.region));
			mqttConf[idx].clientId = stringAppend((CHAR *)mqttConf[idx].clientId,(const CHAR *)KW_REGIS,strlen(KW_REGIS));
			mqttConf[idx].clientId = stringAppend((CHAR *)mqttConf[idx].clientId,(const CHAR *)googleIotConf.regisId,strlen(googleIotConf.regisId));
			mqttConf[idx].clientId = stringAppend((CHAR *)mqttConf[idx].clientId,(const CHAR *)KW_DEV,strlen(KW_DEV));
			mqttConf[idx].clientId = stringAppend((CHAR *)mqttConf[idx].clientId,(const CHAR *)googleIotConf.deviceID,strlen(googleIotConf.deviceID));
			//printf("G ClientID : %s\n",mqttConf[idx].clientId);

			/* Select with or without TLS/SSL */
			mqttConf[idx].sslTlsConfig.withSsl = GOOGLE_BROKER_SSL_ENABLE;
			
			/* Select TLs Version */
			mqttConf[idx].sslTlsConfig.tlsVersion = BROKER_TLSV_1_2;

			/* SSL Type */
			mqttConf[idx].sslTlsConfig.sslType = CERT_KEY; //Now its will support only with certificates

			/* ca files */
			mqttConf[idx].sslTlsConfig.caOnly = GOOGLE_CA_ONLY;
			if(mqttConf[idx].sslTlsConfig.caOnly)
			{
				mqttConf[idx].sslTlsConfig.caCrtFile = GOOGLE_BROKER_CACRT_FILE_NAME;
			}
			else
			{
				mqttConf[idx].sslTlsConfig.caCrtFile = GOOGLE_BROKER_CACRT_FILE_NAME;
				mqttConf[idx].sslTlsConfig.clientCrtFile = GOOGLE_BROKER_CLCRT_FILE_NAME;
				mqttConf[idx].sslTlsConfig.clientKeyFile = GOOGLE_BROKER_CLKEY_FILE_NAME;
				mqttConf[idx].sslTlsConfig.pemPassword = (CHAR *)stringCopy((VOID*)mqttConf[idx].sslTlsConfig.pemPassword,
																			(const VOID *)(GOOGLE_BROKER_CLKEY_PASSWD),
																			(size_t)strlen(GOOGLE_BROKER_CLKEY_PASSWD));
			}

			/* Subscribe  */
			mqttConf[idx].totalSubCount = GOOGLE_BROKER_SUB_COUNT;
			for(i=0;i<mqttConf[idx].totalSubCount;i++)
			{
				if(strlen(GOOGLE_BROKER_SUB_TOPIC) > 0)
				{
					mqttConf[idx].subMqttMsg[i].topic = (CHAR *)stringCopy((VOID*)mqttConf[idx].subMqttMsg[i].topic,
																			(const VOID *)(GOOGLE_BROKER_SUB_TOPIC),
																			(size_t)strlen(GOOGLE_BROKER_SUB_TOPIC));
				}

				mqttConf[idx].subMqttMsg[i].qos = (INT)GOOGLE_BROKER_SUB_QOS;
				//mqttConf[idx].subMqttMsg[i].msgId = (i+1);
			}

			/* Publish */
			mqttConf[idx].totalPubCount = GOOGLE_BROKER_PUB_COUNT;
			for(i=0;i<mqttConf[idx].totalPubCount;i++)
			{
				mqttConf[idx].pubMqttMsg[i].topic = stringAppend((CHAR *)mqttConf[idx].pubMqttMsg[i].topic,(const CHAR *)KW_DEV,strlen(KW_DEV));
				mqttConf[idx].pubMqttMsg[i].topic = stringAppend((CHAR *)mqttConf[idx].pubMqttMsg[i].topic,(const CHAR *)googleIotConf.deviceID,strlen(googleIotConf.deviceID));
				mqttConf[idx].pubMqttMsg[i].topic = stringAppend((CHAR *)mqttConf[idx].pubMqttMsg[i].topic,(const CHAR *)KW_EVENT,strlen(KW_EVENT));

				mqttConf[idx].pubMqttMsg[i].qos = (INT)GOOGLE_BROKER_PUB_QOS;
				mqttConf[idx].pubMqttMsg[i].retain = (GOOGLE_BROKER_PUB_RETAINED)?TRUE:FALSE;

				mqttConf[idx].pubMqttMsg[i].publishType = 1; /*Periodic only*/
				mqttConf[idx].pubMqttMsg[i].perInterval = GOOGLE_BROKER_PUB_PERIODIC_TIME;
				/* Data will be taken from random generator */
			}
		}
		break;
		case IDX_ATNT:
		{
			/* Connection Name */
			mqttConf[idx].mqttConnName = "ATNT";
			
			/* Corresponding Broker Connection enable/disable */
			mqttConf[idx].enable = TRUE;

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

			/* MQTT Broker Ip */
			mqttConf[idx].mqttBrokerIp = (CHAR *)calloc((size_t)strlen(BROKER_ATNT_HOST)+1,sizeof(CHAR));
			strcpy(mqttConf[idx].mqttBrokerIp,BROKER_ATNT_HOST);
			
			/* Broker Port */
			mqttConf[idx].mqttBrokerPort = BROKER_ATNT_PORT;

			/* Username */
			if(strlen(BROKER_ATNT_UNAME) > 0)
			{
				mqttConf[idx].mqttBrokerUname = (CHAR *)stringCopy((VOID*)mqttConf[idx].mqttBrokerUname,
																	(const VOID *)(BROKER_ATNT_UNAME),
																	(size_t)strlen(BROKER_ATNT_UNAME));
			}
			else
				mqttConf[idx].mqttBrokerUname = "";

			/* Password */
			if(strlen(BROKER_ATNT_PASSWD) > 0)
			{
				mqttConf[idx].mqttBrokerPasswd = (CHAR *)stringCopy((VOID*)mqttConf[idx].mqttBrokerPasswd,
															(const VOID *)(BROKER_ATNT_PASSWD),
															(size_t)strlen(BROKER_ATNT_PASSWD));
			}
			else
				mqttConf[idx].mqttBrokerPasswd = "";

			/* Client Id */
			if(strlen(BROKER_ATNT_CLIENT_ID) > 0)
			{
				mqttConf[idx].clientId = (CHAR *)stringCopy((VOID*)mqttConf[idx].clientId,
													(const VOID *)(BROKER_ATNT_CLIENT_ID),
													(size_t)strlen(BROKER_ATNT_CLIENT_ID));
			}
			else
			{
				mqttConf[idx].clientId ="\0";
				mqttConf[idx].cleanSession = TRUE;
			}

			/* Select with or without TLS/SSL */
			mqttConf[idx].sslTlsConfig.withSsl = ATNT_BROKER_SSL_ENABLE;
			
			/* Select TLs Version */
			mqttConf[idx].sslTlsConfig.tlsVersion = BROKER_TLSV_1_2;

			/* SSL Type */
			mqttConf[idx].sslTlsConfig.sslType = CERT_KEY; //Now its will support only with certificates

			/* ca files */
			mqttConf[idx].sslTlsConfig.caOnly = ATNT_CA_ONLY;
			if(mqttConf[idx].sslTlsConfig.caOnly)
			{
				mqttConf[idx].sslTlsConfig.caCrtFile = ATNT_BROKER_CACRT_FILE_NAME;
			}
			else
			{
				mqttConf[idx].sslTlsConfig.caCrtFile = ATNT_BROKER_CACRT_FILE_NAME;
				mqttConf[idx].sslTlsConfig.clientCrtFile = ATNT_BROKER_CLCRT_FILE_NAME;
				mqttConf[idx].sslTlsConfig.clientKeyFile = ATNT_BROKER_CLKEY_FILE_NAME;
				mqttConf[idx].sslTlsConfig.pemPassword = (CHAR *)stringCopy((VOID*)mqttConf[idx].sslTlsConfig.pemPassword,
																			(const VOID *)(ATNT_BROKER_CLKEY_PASSWD),
																			(size_t)strlen(ATNT_BROKER_CLKEY_PASSWD));
			}

			/* Subscribe  */
			mqttConf[idx].totalSubCount = ATNT_BROKER_SUB_COUNT;
			for(i=0;i<mqttConf[idx].totalSubCount;i++)
			{
				if(strlen(ATNT_BROKER_SUB_TOPIC) > 0)
				{
					mqttConf[idx].subMqttMsg[i].topic = (CHAR *)stringCopy((VOID*)mqttConf[idx].subMqttMsg[i].topic,
																			(const VOID *)(ATNT_BROKER_SUB_TOPIC),
																			(size_t)strlen(ATNT_BROKER_SUB_TOPIC));
				}

				mqttConf[idx].subMqttMsg[i].qos = (INT)ATNT_BROKER_SUB_QOS;
				//mqttConf[idx].subMqttMsg[i].msgId = (i+1);
			}

			/* Publish */
			mqttConf[idx].totalPubCount = ATNT_BROKER_PUB_COUNT;
			for(i=0;i<mqttConf[idx].totalPubCount;i++)
			{
				mqttConf[idx].pubMqttMsg[i].topic = stringAppend((CHAR *)mqttConf[idx].pubMqttMsg[i].topic,(const CHAR *)KW_M2X,strlen(KW_M2X));
				mqttConf[idx].pubMqttMsg[i].topic = stringAppend((CHAR *)mqttConf[idx].pubMqttMsg[i].topic,(const CHAR *)attIotConf.primaryApiKey,strlen(attIotConf.primaryApiKey));
				mqttConf[idx].pubMqttMsg[i].topic = stringAppend((CHAR *)mqttConf[idx].pubMqttMsg[i].topic,(const CHAR *)KW_REQUESTS,strlen(KW_REQUESTS));
				mqttConf[idx].pubMqttMsg[i].qos = (INT)ATNT_BROKER_PUB_QOS;
				mqttConf[idx].pubMqttMsg[i].retain = (ATNT_BROKER_PUB_RETAINED)?TRUE:FALSE;

				mqttConf[idx].pubMqttMsg[i].publishType = 1; /*Periodic only*/
				mqttConf[idx].pubMqttMsg[i].perInterval = ATNT_BROKER_PUB_PERIODIC_TIME;
				/* Data will be taken from random generator */
			}
		}
		break;
		default: /* IDX_GENERIC */
		{
			/* Connection Name */
			mqttConf[idx].mqttConnName = "GENERIC";
			
			/* Corresponding Broker Connection enable/disable */
			mqttConf[idx].enable = TRUE;

			/* MQTT Broker Ip */
			mqttConf[idx].mqttBrokerIp = (CHAR *)calloc((size_t)strlen(BROKER_GENERIC_HOST)+1,sizeof(CHAR));
			strcpy(mqttConf[idx].mqttBrokerIp,BROKER_GENERIC_HOST);
			
			/* Broker Port */
			mqttConf[idx].mqttBrokerPort = BROKER_GENERIC_PORT;

			/* Username */
			if(strlen(BROKER_GENERIC_UNAME) > 0)
			{
				mqttConf[idx].mqttBrokerUname = (CHAR *)stringCopy((VOID*)mqttConf[idx].mqttBrokerUname,
																	(const VOID *)(BROKER_GENERIC_UNAME),
																	(size_t)strlen(BROKER_GENERIC_UNAME));
			}
			else
				mqttConf[idx].mqttBrokerUname = "";

			/* Password */
			if(strlen(BROKER_GENERIC_PASSWD) > 0)
			{
				mqttConf[idx].mqttBrokerPasswd = (CHAR *)stringCopy((VOID*)mqttConf[idx].mqttBrokerPasswd,
															(const VOID *)(BROKER_GENERIC_PASSWD),
															(size_t)strlen(BROKER_GENERIC_PASSWD));
			}
			else
				mqttConf[idx].mqttBrokerPasswd = "";

			/* Client Id */
			if(strlen(BROKER_GENERIC_CLIENT_ID) > 0)
			{
				mqttConf[idx].clientId = (CHAR *)stringCopy((VOID*)mqttConf[idx].clientId,
													(const VOID *)(BROKER_GENERIC_CLIENT_ID),
													(size_t)strlen(BROKER_GENERIC_CLIENT_ID));
			}
			else
			{
				mqttConf[idx].clientId ="\0";
				mqttConf[idx].cleanSession = TRUE;
			}

			/* Select with or without TLS/SSL */
			mqttConf[idx].sslTlsConfig.withSsl = GENERIC_BROKER_SSL_ENABLE;
			
			/* Select TLs Version */
			mqttConf[idx].sslTlsConfig.tlsVersion = BROKER_TLSV_1_2;

			/* SSL Type */
			mqttConf[idx].sslTlsConfig.sslType = CERT_KEY; //Now its will support only with certificates

			/* ca files */
			mqttConf[idx].sslTlsConfig.caOnly = GENERIC_CA_ONLY;
			if(mqttConf[idx].sslTlsConfig.caOnly)
			{
				mqttConf[idx].sslTlsConfig.caCrtFile = GENERIC_BROKER_CACRT_FILE_NAME;
			}
			else
			{
				mqttConf[idx].sslTlsConfig.caCrtFile = GENERIC_BROKER_CACRT_FILE_NAME;
				mqttConf[idx].sslTlsConfig.clientCrtFile = GENERIC_BROKER_CLCRT_FILE_NAME;
				mqttConf[idx].sslTlsConfig.clientKeyFile = GENERIC_BROKER_CLKEY_FILE_NAME;
				mqttConf[idx].sslTlsConfig.pemPassword = (CHAR *)stringCopy((VOID*)mqttConf[idx].sslTlsConfig.pemPassword,
																			(const VOID *)(GENERIC_BROKER_CLKEY_PASSWD),
																			(size_t)strlen(GENERIC_BROKER_CLKEY_PASSWD));
			}

			/* Subscribe  */
			mqttConf[idx].totalSubCount = GENERIC_BROKER_SUB_COUNT;
			for(i=0;i<mqttConf[idx].totalSubCount;i++)
			{
				if(strlen(GENERIC_BROKER_SUB_TOPIC) > 0)
				{
					mqttConf[idx].subMqttMsg[i].topic = (CHAR *)stringCopy((VOID*)mqttConf[idx].subMqttMsg[i].topic,
																			(const VOID *)(GENERIC_BROKER_SUB_TOPIC),
																			(size_t)strlen(GENERIC_BROKER_SUB_TOPIC));
				}

				mqttConf[idx].subMqttMsg[i].qos = (INT)GENERIC_BROKER_SUB_QOS;
				//mqttConf[idx].subMqttMsg[i].msgId = (i+1);
			}

			/* Publish */
			mqttConf[idx].totalPubCount = GENERIC_BROKER_PUB_COUNT;
			for(i=0;i<mqttConf[idx].totalPubCount;i++)
			{
				mqttConf[idx].pubMqttMsg[i].topic = (CHAR *)stringCopy((VOID*)mqttConf[idx].pubMqttMsg[i].topic,
										(const VOID *)(GENERIC_BROKER_PUB_TOPIC),(size_t)strlen(GENERIC_BROKER_PUB_TOPIC));
				mqttConf[idx].pubMqttMsg[i].qos = (INT)GENERIC_BROKER_PUB_QOS;
				mqttConf[idx].pubMqttMsg[i].retain = (GENERIC_BROKER_PUB_RETAINED)?TRUE:FALSE;

				mqttConf[idx].pubMqttMsg[i].publishType = 1; /*Periodic only*/
				mqttConf[idx].pubMqttMsg[i].perInterval = GENERIC_BROKER_PUB_PERIODIC_TIME;
				/* Data will be taken from random generator */
			}
		}
		break;
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

VOID getValueAndConsJson(MQTT_CONFIG *mqttConf,UINT32 pubIndex,INT32 idx)
{
	CHAR tempBuff[512] = {0};
	INT value = 0;
	struct tm *timeptr = NULL;
	time_t temp;

	switch(idx)
	{
		case IDX_ATNT:
		{
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
			randNumberGen(1,100,&value);
			sprintf(tempBuff,"\"value\":%d}]}}",value);
			mqttConf->pubMqttMsg[pubIndex].msg = stringAppend((CHAR *)mqttConf->pubMqttMsg[pubIndex].msg,(const CHAR *)tempBuff,strlen(tempBuff));
		}
		break;
		case IDX_AWS:
		case IDX_AZURE:
		case IDX_GOOGLE:
		{
			temp = time(NULL);
			timeptr = gmtime(&temp);
			memset(tempBuff,0,sizeof(tempBuff));
			strftime(tempBuff,sizeof(tempBuff)-1,"{\"Time\":\"%FT%I:%M:%S.000Z\",", timeptr); 
			mqttConf->pubMqttMsg[pubIndex].msg = stringAppend((CHAR *)mqttConf->pubMqttMsg[pubIndex].msg,(const CHAR *)tempBuff,strlen(tempBuff));
			
			memset(tempBuff,0,sizeof(tempBuff));
			randNumberGen(1,100,&value);
			sprintf(tempBuff,"\"Testvalue\":%d}",value); 
			mqttConf->pubMqttMsg[pubIndex].msg = stringAppend((CHAR *)mqttConf->pubMqttMsg[pubIndex].msg,(const CHAR *)tempBuff,strlen(tempBuff));
		}
		break;
		case IDX_HORNER:
		default:  /* IDX_GENERIC */
		{
			memset(tempBuff,0,sizeof(tempBuff));
			temp = time(NULL);
			timeptr = gmtime(&temp);
			strftime(tempBuff,sizeof(tempBuff)-1,"{\"Time\":\"%FT%I:%M:%S.000Z\",", timeptr); 
			mqttConf->pubMqttMsg[pubIndex].msg = stringAppend((CHAR *)mqttConf->pubMqttMsg[pubIndex].msg,(const CHAR *)tempBuff,strlen(tempBuff));
			
			memset(tempBuff,0,sizeof(tempBuff));
			randNumberGen(1,100,&value);
			sprintf(tempBuff,"\"Testvalue\":%d}",value); 
			mqttConf->pubMqttMsg[pubIndex].msg = stringAppend((CHAR *)mqttConf->pubMqttMsg[pubIndex].msg,(const CHAR *)tempBuff,strlen(tempBuff));
		}
		break;
	}

	mqttConf->pubMqttMsg[pubIndex].msgLen = strlen((const CHAR *)mqttConf->pubMqttMsg[pubIndex].msg);
	mqttConf->pubMqttMsg[pubIndex].dataLoaded = TRUE;

	printf("Json :\n%s\n",(CHAR *)mqttConf->pubMqttMsg[pubIndex].msg);

	return;
}

/* GOOGLE */
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

INT main(VOID)
{
	INT32 index = 0, idxBc = 0;
	//UINT8 value = 0;
	time_t curSec = 0;

	if(onetime)
	{
		onetime = FALSE;
		for(idxBc=0; idxBc < MAX_BROKER_CONNECTION; idxBc++ ) //each broker state control
			readConfig(idxBc);

		mqttLibInit();
	}
	
	while(1)
	for(idxBc=0; idxBc < MAX_BROKER_CONNECTION; idxBc++ ) //each broker state control
	{
		switch(mqttConf[idxBc].nextMqttState)
		{
			case STATE_CONNECT:
			{
				if(!mqttConnect(&mqttConf[idxBc]))
				{
					SET_STATE(STATE_DISCONNECT);
				}
				else
				{
					checkTimeout(&mqttConf[idxBc].conTickTime,0); //Start Time
					SET_ST_EV(STATE_IDLE,EVENT_CONNECT_SENT);
				}
			}
			break;
			case STATE_DISCONNECT:
			{
				mqttDisconnect(&mqttConf[idxBc]);
				checkTimeout(&mqttConf[idxBc].disConTickTime,0); //Start Time
				SET_ST_EV(STATE_IDLE,EVENT_DISCONNECT_SENT);
			}
			break;
			case STATE_PUBLISH:
			{
				for(index=0;index<mqttConf[idxBc].totalPubCount;index++)
				{
					if( mqttConf[idxBc].pubMqttMsg[index].dataLoaded /* && !mqttConf.pubMqttMsg[index].sending */)
					{
						mqttPublish(&mqttConf[idxBc],index);
					}
				}
				SET_ST_EV(STATE_IDLE,EVENT_EMPTY);
			}
			break;
			case STATE_SUBSCRIBE:
			{
				for(index=0;index<mqttConf[idxBc].totalSubCount;index++)
				{
					if( !mqttConf[idxBc].subMqttMsg[index].msgStatus.subscribeDataStatus &&
						!mqttConf[idxBc].subMqttMsg[index].msgStatus.subscribeCmdSent )
					{
						//Subscribe
						if( mqttSubscribe(&mqttConf[idxBc],index) )
							checkTimeout(&mqttConf[idxBc].subMqttMsg[index].subTickTime,0); //Start Time
					}
				}
				SET_ST_EV(STATE_IDLE,EVENT_EMPTY);
			}
			break;
			case STATE_PROC_MSG:
			{
				//procMsgToReg(&mqttConf[idxBc]);
				SET_ST_EV(STATE_IDLE,EVENT_EMPTY);
			}
			break;
			default:
			{
				switch(mqttConf[idxBc].nextMqttEvent)
				{
					case EVENT_CONNECT_SENT:
					{
						if(mqttConf[idxBc].clientStatus.isBrokerConnected)
						{
							SET_STATE(STATE_SUBSCRIBE);
						}
						else
						{
							if( checkTimeout(&mqttConf[idxBc].conTickTime,(10)) ) //10 sec
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
						/* if( checkTimeout(&mqttConf[idxBc].disConTickTime,(US_1_MS*3000)) ) //5 sec */
						if( checkTimeout(&mqttConf[idxBc].disConTickTime,(3)) )
						{
							mqttConf[idxBc].clientStatus.isBrokerConnected = FALSE;
							SET_STATE(STATE_CONNECT);
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
						if(mqttConf[idxBc].clientStatus.isBrokerConnected)
						{
							/**	Check timeout or trigger to publish the data(json) **/
							if(mqttConf[idxBc].clientType == PUBLISHER || mqttConf[idxBc].clientType == PUB_SUB_BOTH )
							{
								for(index=0;index<mqttConf[idxBc].totalPubCount;index++)
								{
									if( checkTimeout(&mqttConf[idxBc].pubMqttMsg[index].perIntervalTime,
													  mqttConf[idxBc].pubMqttMsg[index].perInterval) )
									{
										checkTimeout(&mqttConf[idxBc].pubMqttMsg[index].perIntervalTime,0);
										//construct json with given reg details
										printf("\nTime to send Data..Broker - %ld\n",idxBc);
										getValueAndConsJson(&mqttConf[idxBc],index,idxBc);
										SET_STATE(STATE_PUBLISH);
									}
								}
							}
							
							/* GOOGLE */
							if(idxBc == IDX_GOOGLE)
							{
								/* Reconnect if JWT is expired */
								curSec = time(NULL);
								googleIotConf.jwtInfos.secsFromIssue = curSec - googleIotConf.jwtInfos.iatTimeInsec;
								if(googleIotConf.jwtInfos.secsFromIssue > (googleIotConf.jwtInfos.expTime - 15) ) /* before 15 sec reconnect */
								{
									printf("Token generated before %d \n",googleIotConf.jwtInfos.secsFromIssue);
									updateGooglePasswd(&googleIotConf,&mqttConf[idxBc]);
									printf("Config Updated....\n");
									SET_STATE(STATE_CONNECT);
								}
							}
						}
						else
						{
							/* GOOGLE */
							if(idxBc == IDX_GOOGLE)
							{
								updateGooglePasswd(&googleIotConf,&mqttConf[idxBc]);
								printf("Config Updated..\n");
								SET_STATE(STATE_DISCONNECT);
							}
						}
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