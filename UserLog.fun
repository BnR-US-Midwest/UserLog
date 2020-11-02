
FUNCTION LogEvent : UDINT (*Add an event to the FIFO buffer which writes entries to the user logbook*)
	VAR_INPUT
		Severity : UserLogSeverityEnum; (*Set the severity level of the logbook entry*)
		Code : UINT; (*Set the unique code for this logbook entry*)
		sMessage : STRING[USER_LOG_MESSAGE_LENGTH]; (*Message written to the ASCII data of the logbook entry*)
	END_VAR
END_FUNCTION

FUNCTION_BLOCK CyclicUserLogBuffer (*Write buffered entries to the user logbook*)
	VAR_OUTPUT
		ReturnValue : UDINT; (*Return status value for the user*)
	END_VAR
END_FUNCTION_BLOCK
