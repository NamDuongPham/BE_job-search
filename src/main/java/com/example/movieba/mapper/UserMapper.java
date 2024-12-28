package com.example.movieba.mapper;

import com.example.movieba.entities.User;
import com.example.movieba.model.request.user.UserInfoRequest;
import com.example.movieba.model.response.UserInfoResponse;
import com.example.movieba.utils.BeanUtils;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.security.NoSuchAlgorithmException;

@Component
@AllArgsConstructor
public class UserMapper implements Mapper{

    private final PasswordEncoder passwordEncoder;
    public User to(UserInfoRequest userInfoRequest){

            User user = new User();
            BeanUtils.refine(userInfoRequest,user,BeanUtils::copyNonNull);
            String password = passwordEncoder.encode(userInfoRequest.getPassword());
            user.setPassword(password);
            return user;
    }

    public UserInfoResponse from(User user){
        UserInfoResponse userInfoResponse = new UserInfoResponse();
        BeanUtils.refine(user,userInfoResponse,BeanUtils::copyNonNull);
        return userInfoResponse;
    }
}
