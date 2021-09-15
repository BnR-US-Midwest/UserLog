/*********************************************************************************
 * File:      UserLogMain.h
 * Author:    Tyler Matijevich
 * Created:   October 21, 2020/21:31 
 *********************************************************************************/ 

#ifndef __USER_LOG_MAIN_H__
#define __USER_LOG_MAIN_H__

#include <UserLog.h>
#include <string.h>
#include <stdbool.h>

typedef struct UserLogBufferEntryType {
	enum UserLogSeverityEnum severity;
	unsigned short code;
	char message[USERLOG_MESSAGE_LENGTH + 1];
	char task[37]; /* Defined by ArEventLogWrite() */
} UserLogBufferEntryType;

/* Reference with a promise these variables will be declared in a source file */
extern UserLogBufferEntryType buffer[USERLOG_BUFFER_SIZE];
extern UserLogBufferInfoType info;
extern UserLogSeverityEnum severityThreshold;
extern unsigned char promptFull;
extern unsigned char promptEmpty;

#endif /* __USER_LOG_MAIN_H__ */
