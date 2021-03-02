#ifndef CONFIGSELECTION_H
#define CONFIGSELECTION_H

#define	ATNT		1
#define	AWS			0
#define	AZURE		0
#define	GOOGLE		0
#define	SPARKPLUG	0

/* BROKER DETAILS */
#define BROKER_CLEAN_SESSION			TRUE
#define BROKER_KEEP_ALIVE				60	/* in sec */
#define BROKER_CLIENT_TYPE				3   /* PUBLISHER = 1, SUBSCRIBER = 2, PUB_SUB_BOTH = 3*/
#if ATNT
	#define ATNT_DEVICE_NAME				"OCS"
	#define ATNT_DEVICE_ID					"c80ad86ccacfa015773a182d6dc6de9a"
	#define ATNT_PRIMARY_ENDPOINT			"/devices/c80ad86ccacfa015773a182d6dc6de9a"
	#define ATNT_PRIMARY_API_KEY			"b71654e9857aac858772b56398516b97"
	#define ATNT_STREAMID					"x5_r1"

	#define BROKER_CLIENT_ID				ATNT_DEVICE_ID /* Should be Unique */
	#define BROKER_HOST						"api-m2x.att.com" /* IP or DOMAIN */
	#define BROKER_PORT						1883
	#define BROKER_UNAME					ATNT_PRIMARY_API_KEY
	#define BROKER_PASSWD					""
#elif AWS
	#define BROKER_CLIENT_ID				"myAwsIotDevice_1" /* Should be Unique */
	#define BROKER_HOST						"at1m38pe47h5p.iot.us-east-1.amazonaws.com" /* IP or DOMAIN */
	#define BROKER_PORT						8883
	#define BROKER_UNAME					""
	#define BROKER_PASSWD					""
#elif AZURE
	#define BROKER_CLIENT_ID				"mytesthorneriotdevice" /* Should be Unique */
	#define BROKER_HOST						"hornerNewBroker.azure-devices.net" /* IP or DOMAIN */
	#define BROKER_PORT						8883
	#define BROKER_UNAME					"hornerNewBroker.azure-devices.net/mytesthorneriotdevice"
	#define BROKER_PASSWD					""
#elif GOOGLE
	#define BROKER_HOST						"mqtt.googleapis.com" /* IP or DOMAIN */
	#define BROKER_PORT						8883
	#define BROKER_UNAME					"unused"

	/* BROKER_CLIENT_ID and BROKER_PASSWD will generated by using below parameters */
	#define GOOGLE_PROJECT_ID				"TestMqttProject"
	#define GOOGLE_REGIS_ID					"TestRegister"
	#define GOOGLE_DEVICE_ID				"TestDevice"
	#define GOOGLE_REGION					"asia-east1"

	/* Refer http://benmcollins.github.io/libjwt/globals_eval.html */
	#define GOOGLE_ALG_TYPE					4

	#define GOOGLE_JWT_EXP_TIME				0 /* Min allowed 10 min (600 sec)*/
#elif SPARKPLUG //Third Party
	#define BROKER_CLIENT_ID				"mytestsparkplugnode" /* Should be Unique */
	#define BROKER_HOST						"162.255.87.22" /* IP or DOMAIN */
	#define BROKER_PORT						1883
	#define BROKER_UNAME					"ganesh"
	#define BROKER_PASSWD					"ganesh"
#endif

/* SSL/TLS */
#if ATNT
	#define BROKER_SSL_ENABLE				FALSE
	#define CA_ONLY							FALSE
	#define BROKER_CACRT_FILE_NAME			""
	#define BROKER_CLCRT_FILE_NAME			""
	#define BROKER_CLKEY_FILE_NAME			""
	#define BROKER_CLKEY_PASSWD				""
#elif AWS
	#define BROKER_SSL_ENABLE				TRUE
	#define CA_ONLY							FALSE
	#define BROKER_CACRT_FILE_NAME			"./aws/rootCA.pem"
	#define BROKER_CLCRT_FILE_NAME			"./aws/deviceCert.pem"
	#define BROKER_CLKEY_FILE_NAME			"./aws/deviceCert.key"
	#define BROKER_CLKEY_PASSWD				""
#elif AZURE
	#define BROKER_SSL_ENABLE				TRUE
	#define CA_ONLY							FALSE
	#define BROKER_CACRT_FILE_NAME			"./azure/rootCA.crt"
	#define BROKER_CLCRT_FILE_NAME			"./azure/new-device.cert.pem"
	#define BROKER_CLKEY_FILE_NAME			"./azure/new-device.key.pem"
	#define BROKER_CLKEY_PASSWD				"1234"
#elif GOOGLE
	#define BROKER_SSL_ENABLE				TRUE
	#define CA_ONLY							TRUE
	#define BROKER_CACRT_FILE_NAME			"./google/roots.pem"
	#define BROKER_CLCRT_FILE_NAME			"./google/rsa_private1.pem" /* Private key to generate JWT */
	#define BROKER_CLKEY_FILE_NAME			""
	#define BROKER_CLKEY_PASSWD				""
#elif SPARKPLUG
	#define BROKER_SSL_ENABLE				FALSE
	#define CA_ONLY							FALSE
	#define BROKER_CACRT_FILE_NAME			""
	#define BROKER_CLCRT_FILE_NAME			""
	#define BROKER_CLKEY_FILE_NAME			""
	#define BROKER_CLKEY_PASSWD				""
#endif

#define BROKER_TLSV_1					"tlsv1"
#define BROKER_TLSV_1_1					"tlsv1.1"
#define BROKER_TLSV_1_2					"tlsv1.2"

/* The below configuration will change as per broker */
/* Subscribe Details */
#define BROKER_SUB_COUNT				0
#define BROKER_SUB_TOPIC				"m2x/#"
#define BROKER_SUB_QOS					1

/* Publish Details */
#define BROKER_PUB_COUNT				1
#define BROKER_PUB_QOS					0
#define BROKER_PUB_RETAINED				FALSE
//#define BROKER_PUB_TOPIC				"devices/mytesthorneriotdevice/messages/events/sampleData" /* BROKER_PUB_TOPIC will generated by using deviceID for Google & att */
#define BROKER_PUB_TOPIC				"aws/requests" /* BROKER_PUB_TOPIC will generated by using deviceID for Google & att & SPARKPLUG */
#define BROKER_PUB_PERIODIC_TIME		5 /*in sec*/

#if SPARKPLUG
	#define	SP_NAME_SPACE					"spBv1.0"
	#define	SP_GROUP_ID						"hornerOCS"
	#define	SP_NODE_ID						"x5"
#endif

#endif
//http://benmcollins.github.io/libjwt/globals_eval.html
/* EOF */