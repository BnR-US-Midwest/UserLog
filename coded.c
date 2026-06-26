/*******************************************************************************
 * File: coded.c
 * Created: 2023-02-03
 * 
 * Authors: 
 *   Tyler Matijevich
 * 
 * License:
 *   This file coded.c is part of the UserLog project 
 *   released under the MIT license agreement.
 ******************************************************************************/

#include "Main.h"

/* Write to any user logbook through binary-encoded data and event texts */
ArEventLogRecordIDType UserLogEventText(char *Logbook, int32_t Event, 
    ArEventLogRecordIDType Origin, 
    char *Object, char *Message, 
    UserLogFormatType *Values)
{
    /* Suppress message */
    if (UserLogGetSeverity(Event) < severity_level) return 0;

    /* Get logbook identifier */
    ArEventLogGetIdent_typ get_ident = {{0}};
    IecStringCopy(get_ident.Name, sizeof(get_ident.Name), Logbook);
    get_ident.Execute = true;
    ArEventLogGetIdent(&get_ident);

    /* Check for error */
    static uint8_t error;
    UserLogFormatType log_values = {{0}};
    if (get_ident.StatusID) 
    {
        /* Block infinite recursion */
        if (error) return 0;
        
        /* Log error */
        log_values.i[0] = get_ident.StatusID;
        IecStringCopy(log_values.s[0], sizeof(log_values.s[0]), Logbook);
        log_values.i[1] = Event;
        UserLogCustom(LOGBOOK_USER_NAME, USERLOG_SEVERITY_ERROR,
            FACILITY_ERROR, CODE_ERROR_IDENT, 0, NULL,
            "ArEventLog error %i writing to logbook \"%s\" "
            "with event ID %i using UserLog", &log_values);
        error = true;
        return 0;
    }
    
    /* Write to identified logbook */
    ArEventLogWrite_typ write = {0};
    write.Ident = get_ident.Ident;

    /* Event ID */
    write.EventID = Event;

    /* Add binary-coded data */ 
    // Each Value is encoded as a separate argument 
    // These are referenced by the event text's format items {1}, {2}, ...
    // Message specifiers (%b, %i, %f, %s) define only the order and type 
    char data[DATA_CODED_SIZE] = {0};
    char argument[DATA_MESSAGE_SIZE];
    ArEventLogAddDataInit((uint32_t)data, sizeof(data), 
        arEVENTLOG_ADDFORMAT_CODED);

    if (Message && Values)
    {
        int count_bool = 0, count_float = 0, count_int = 0, count_string = 0;
        char *source = Message;
        while (*source)
        {
            // Only format specifiers contribute coded arguments
            if (*source != '%')
            {
                source++;
                continue;
            }

            switch (*(++source))
            {
                // Boolean converted to a string
                case 'b':
                    if (count_bool > USERLOG_FORMAT_INDEX) break;
                    IecStringCopy(argument, sizeof(argument),
                        Values->b[count_bool++] ? "TRUE" : "FALSE");
                    ArEventLogAddDataString((uint32_t)data, sizeof(data),
                        (uint32_t)argument);
                    break;

                // LREAL/double casted to REAL/float
                case 'r':
                case 'f':
                    if (count_float > USERLOG_FORMAT_INDEX) break;
                    IecStringFloat(argument, sizeof(argument),
                        (float)Values->f[count_float++], 0, 6,
                        IECSTRING_FLAG_NONE);
                    ArEventLogAddDataString((uint32_t)data, sizeof(data),
                        (uint32_t)argument);
                    break;

                // Integer/decimal
                case 'i':
                case 'd':
                    if (count_int > USERLOG_FORMAT_INDEX) break;
                    IecStringDecimal(argument, sizeof(argument),
                        Values->i[count_int++], 0, IECSTRING_FLAG_NONE);
                    ArEventLogAddDataString((uint32_t)data, sizeof(data),
                        (uint32_t)argument);
                    break;

                // String
                case 's':
                    if (count_string > USERLOG_FORMAT_INDEX) break;
                    ArEventLogAddDataString((uint32_t)data, sizeof(data),
                        (uint32_t)Values->s[count_string++]);
                    break;
            }

            if (*source) source++;
        }
    }

    write.AddDataSize = sizeof(data);
    write.AddDataFormat = arEVENTLOG_ADDFORMAT_CODED;
    write.AddData = (uint32_t)data;

    /* Object name */
    if (!Object || !*Object)
        ST_name(0, write.ObjectID, 0);
    else
        IecStringCopy(write.ObjectID, sizeof(write.ObjectID), Object);

    /* Write to logbook */
    write.Execute = true;
    ArEventLogWrite(&write);

    /* Check for error */
    if (write.StatusID)
    {
        /* Block infinite recursion */
        if (error) return 0;

        /* Log error */
        log_values.i[0] = write.StatusID;
        IecStringCopy(log_values.s[0], sizeof(log_values.s[0]), Logbook);
        log_values.i[1] = Event;
        UserLogCustom(LOGBOOK_USER_NAME, USERLOG_SEVERITY_ERROR,
            FACILITY_ERROR, CODE_ERROR_WRITE, 0, NULL,
            "ArEventLog error %i writing to logbook \"%s\" "
            "with event ID %i using UserLog", &log_values);
        error = true;
        return 0;
    }

    /* No error, share record */
    error = false;
    return write.RecordID;
}
