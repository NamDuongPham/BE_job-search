package com.example.movieba.exception;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class BusinessException extends RuntimeException{
    private transient ErrorResponse errorResponse;

    public BusinessException( ErrorResponse errorResponse) {
        this.errorResponse = errorResponse;
    }
}
