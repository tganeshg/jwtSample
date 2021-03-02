/*******************************************************************/
/* platform.h - Global Standard and Platform-Dependent Definitions */
/*******************************************************************/
#ifndef GENERAL_H
#define GENERAL_H
/*****************************************/
/* Global Standard Data Type Definitions */
/*****************************************/

/* Standard Data Types */
typedef void			VOID;
typedef char			CHAR;
typedef int				INT;
typedef unsigned char	BOOL;		/* TRUE or FALSE		*/
typedef unsigned int	BIT_FIELD;	/* More readable		*/
typedef unsigned char	UINT8;		/* 8-bit unsigned int	*/
typedef signed char		INT8;		/* 8-bit signed int		*/
typedef unsigned int	UINT16;		/* 16-bit unsigned int	*/
typedef signed int		INT16;		/* 16-bit signed int	*/
typedef unsigned long	UINT32;		/* 32-bit unsigned int	*/
typedef signed long		INT32;		/* 32-bit signed int	*/
//typedef unsupported	UINT64;		/* 64-bit unsigned int	*/
//typedef unsupported	INT64;		/* 64-bit signed int	*/
typedef float			FP32;		/* 32-bit real number	*/
//typedef unsupported	FP64;		/* 64-bit real number	*/
//typedef unsupported	FP80;		/* 80-bit real number	*/

/* Legacy Data Types */
typedef unsigned char	BYTE;		/* Same as UINT8		*/
typedef unsigned int	WORD;		/* Same as UINT16		*/
typedef unsigned long	DWORD;		/* Same as UINT32		*/
typedef signed long		LONG;		/* Same as INT32		*/

/* Standard Data Type Modifiers */
#ifndef NEAR
#define NEAR			near		/* Force small model	*/
#endif
#ifndef FAR
#define FAR				far			/* Force large model	*/
#endif


/*************************************/
/* Global Standard Macro Definitions */
/*************************************/

/* The null pointer */
#ifndef NULL
#define NULL				((void *)0)
#endif

/* BOOL values */
#define TRUE				1
#define FALSE				0

/* LOW, HIGH Macros - Extract low or high byte from a word */
#define LOW(w)				((BYTE)(w))
#define HIGH(w) 			((BYTE)((w) >> 8))

/* LOWW, HIGHW Macros - Extract low or high word from a dword */
#define	LOWW(dw)			((WORD)(dw))
#define	HIGHW(dw)			((WORD)((dw) >> 16))

/* Macro to swap the bytes in a word */
#define SWAP(w) 			(((w) << 8) | ((w) >> 8))

/* Macro to swap the words in a dword */
#define SWAPW(dw)			(((dw) << 16) | ((dw) >> 16))

/* Macro to divide two integers with round-up	*/
/* Works best if b is even						*/
#define	DIV_ROUND(a, b)		(((a) + ((b) / 2)) / (b))

/* Macro to find the lowest or highest of two values */
#define MIN(a, b)			(((a) < (b)) ? (a) : (b))
#define MAX(a, b)			(((a) > (b)) ? (a) : (b))

/* Macro to test a value (b) against limits (a and c) */
#define WITHIN(a, b, c)		((b) < (a) ? FALSE : ((b) > (c) ? FALSE : TRUE))

/* Macro to force a value (b) to be within limits (a and c) */
#define LIMIT(a, b, c) 		((b) < (a) ? (a) : ((b) > (c) ? (c) : (b)))


/*************************************/
/* Global Platform-Dependent Defines */
/*************************************/


/*******************************************/
/* Global Platform-Dependent Include Files */
/*******************************************/

#endif
/* EOF */