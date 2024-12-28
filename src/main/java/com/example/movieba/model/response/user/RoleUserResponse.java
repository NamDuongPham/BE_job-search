package com.example.movieba.model.response.user;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class RoleUserResponse {
    private String roleName;
    private long userId;

    private long comId;

}
