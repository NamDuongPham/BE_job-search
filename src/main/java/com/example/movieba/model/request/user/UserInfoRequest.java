package com.example.movieba.model.request.user;



import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@Data
public class UserInfoRequest {

    private String email;
    private String userName;
    private String password;
}
