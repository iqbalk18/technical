package com.testswadharmadutadata.swadharmadutadata.exception;

public class CustomException extends RuntimeException{
        public CustomException(String message) {
            super(message);
        }

        public CustomException(String message, Throwable cause) {
            super(message, cause);
        }
}

