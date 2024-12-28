package com.example.movieba.model.request.user;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class PasswordRequest {
    private String newPassword;
    private String newPasswordT;
}
