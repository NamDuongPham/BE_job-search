package com.example.movieba.model.request.user;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class ResetPasswordRequest {
    private String userName;
    private String email;
}
