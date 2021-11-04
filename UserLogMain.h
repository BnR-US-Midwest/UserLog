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

/* Reference with a promise these variables will be declared in a source file */
extern UserLogInfoType info;
extern UserLogSeverityEnum verbosityLevel;
extern unsigned char severityMap[];

#endif /* __USER_LOG_MAIN_H__ */
