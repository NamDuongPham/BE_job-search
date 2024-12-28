package com.example.movieba.utils;

import jakarta.servlet.http.HttpServletRequest;

public class JwtUtils {
    public static final String AUTH_HEADER = "Authorization";

    public static String getToken(HttpServletRequest request){
        String authHeader = request.getHeader(AUTH_HEADER);
        if (authHeader.startsWith("Bearer ")){
            return authHeader.substring(7);
        }
        return null;

    }

}
