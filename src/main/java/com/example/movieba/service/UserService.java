package com.example.movieba.service;

import com.example.movieba.entities.Cv;
import com.example.movieba.entities.News;
import com.example.movieba.model.request.user.PasswordRequest;
import com.example.movieba.model.request.user.ProfileRequest;
import com.example.movieba.model.request.user.ResetPasswordRequest;
import com.example.movieba.model.request.user.UserInfoRequest;
import com.example.movieba.model.response.UserInfoResponse;
import com.example.movieba.model.response.user.RoleUserResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

public interface UserService {
    String createUser(UserInfoRequest infoRequest);

    String createCompany(UserInfoRequest infoRequest);

    UserInfoResponse infoUser(HttpServletRequest request);

    UserInfoResponse infoById(long id);

    String updatePassword(HttpServletRequest request, PasswordRequest passwordRequest);

    UserInfoResponse updateProfile(HttpServletRequest request, ProfileRequest profileRequest);

    List<String> roleUser(HttpServletRequest request);

    Page<UserInfoResponse> getAll(Pageable pageable);

    List<UserInfoResponse> getUsers();

    int getTotalUser();

    void addCompany(long id, long role);

    void changeStatusAccount(long id, long status);

    RoleUserResponse getRole(HttpServletRequest request);

    UserInfoResponse updateImage(HttpServletRequest request, MultipartFile file);

    List<Cv> getCvs(long userId);

    List<News> getJobFavorite(long userId);

    void addNewFavourite(long userId, long newId);



    String resetPassword( ResetPasswordRequest resetPasswordRequest);
}
