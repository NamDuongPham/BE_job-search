package com.example.movieba.security;

import com.example.movieba.entities.Role;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Setter
@Getter
public class Payload {
    private String username;
    private List<Role> roles;
}
