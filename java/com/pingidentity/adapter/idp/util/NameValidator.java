package com.pingidentity.adapter.idp.util;

import org.apache.commons.validator.GenericValidator;
import org.apache.commons.validator.ValidatorException;

public class NameValidator
{
  public static final int MAX_LENGTH = 128;
  public static final String EMPTY_ERR_MSG = "Name is blank or NULL.";
  public static final String LENGTH_ERR_MSG = "Name exceeds maximum of 128 characters.";
  public static final String INVALID_ERR_MSG = "Name contains invalid characters.";
  private static final String REGEX_ALLOWED = "[a-zA-Z0-9 _\\.\\-]+";
  
  public void validate(String name)
    throws ValidatorException
  {
    if (GenericValidator.isBlankOrNull(name)) {
      throw new ValidatorException("Name is blank or NULL.");
    }
    if (!GenericValidator.maxLength(name, 128)) {
      throw new ValidatorException("Name exceeds maximum of 128 characters.");
    }
    if (!GenericValidator.matchRegexp(name, "[a-zA-Z0-9 _\\.\\-]+")) {
      throw new ValidatorException("Name contains invalid characters.");
    }
  }
}
