package uk.parsec.onelogin.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import java.text.SimpleDateFormat;

public class JsonUtil
{
	public static ObjectMapper makeObjectMapper()
	{
		return
				new ObjectMapper()
						.registerModule(new JavaTimeModule())
						.setDateFormat(new SimpleDateFormat());
	}
}