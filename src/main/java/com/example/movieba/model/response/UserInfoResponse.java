package com.example.movieba.model.response;


import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class UserInfoResponse {
    private Long userId;
    private String userName;
    private String fullName;
    private String email;
    private String avatar;
    private String address;
    private Long total;
    private int status;

}
