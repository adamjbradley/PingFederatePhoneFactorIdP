package com.pingidentity.adapter.idp.util;

import org.apache.commons.validator.GenericValidator;
import org.apache.commons.validator.ValidatorException;

public class EmailValidator
{
  public static final String EMPTY_ERR_MSG = "Email is blank or NULL.";
  public static final String INVALID_FORMAT_ERR_MSG = "Invalid email.";
  public static final String INVALID_CHAR_ERR_MSG = "Email contains invalid characters.";
  private static final String REGEX_ALLOWED = "[a-zA-Z0-9\\+@_\\.\\-]+";
  
  public void validate(String email)
    throws ValidatorException
  {
    if (GenericValidator.isBlankOrNull(email)) {
      throw new ValidatorException("Email is blank or NULL.");
    }
    if (!GenericValidator.matchRegexp(email, "[a-zA-Z0-9\\+@_\\.\\-]+")) {
      throw new ValidatorException("Email contains invalid characters.");
    }
    if (!GenericValidator.isEmail(email)) {
      throw new ValidatorException("Invalid email.");
    }
  }
}
