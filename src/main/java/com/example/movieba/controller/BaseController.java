package com.example.movieba.controller;

import com.example.movieba.exception.BusinessCode;
import com.example.movieba.model.response.BaseResponse;
import org.springframework.http.ResponseEntity;

public abstract class BaseController {
    public ResponseEntity<BaseResponse> success(){
        return ResponseEntity.ok(new BaseResponse(BusinessCode.SUCCESS));
    }

    public ResponseEntity<BaseResponse> success(Object data){
        return ResponseEntity.ok(new BaseResponse(BusinessCode.SUCCESS,data));
    }
}
