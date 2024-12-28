package com.example.movieba.model.response;


import com.example.movieba.exception.ErrorResponse;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class BaseResponse {
    private String code;
    private String message;
    private int status;
    private Object data;

    public BaseResponse(ErrorResponse error) {
        this.code = error.getCode();
        this.message = error.getMessage();
        this.status = error.getStatus().value();
    }

    public BaseResponse(ErrorResponse error, Object data) {
        this.code = error.getCode();
        this.message = error.getMessage();
        this.status = error.getStatus().value();
        this.data = data;
    }
}
