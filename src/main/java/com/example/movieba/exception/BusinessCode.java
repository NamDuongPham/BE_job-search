package com.example.movieba.exception;

import org.springframework.http.HttpStatus;

public final class BusinessCode {

    public static final ErrorResponse SUCCESS = new ErrorResponse("BACKEND-SUCCESS","SUCCESS", HttpStatus.OK);

    public static final ErrorResponse USER_NOT_FOUND = new ErrorResponse("BACKEND-SUCCESS","NOT_FOUND",HttpStatus.NOT_FOUND);

    public static final ErrorResponse GAME_NOT_FOUND = new ErrorResponse("BACKEND-SUCCESS","NOT_FOUND",HttpStatus.NOT_FOUND);

    public static final ErrorResponse GIFT_CODE_NOT_FOUND = new ErrorResponse("BACKEND-SUCCESS","NOT_FOUND",HttpStatus.NOT_FOUND);

    public BusinessCode() {
    }
}
