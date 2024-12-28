package com.example.movieba.controller;

import com.example.movieba.model.request.user.PasswordRequest;
import com.example.movieba.model.request.user.ProfileRequest;
import com.example.movieba.model.response.BaseResponse;
import com.example.movieba.service.CvService;
import com.example.movieba.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@AllArgsConstructor
@RequestMapping("/api/v2")
public class UserController extends BaseController{
    private final UserService userService;

    private final CvService cvService;

    @PutMapping("/update-pass")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') OR hasAuthority('ROLE_USER') OR hasAuthority('ROLE_STAFF')")
    ResponseEntity<BaseResponse> changePass(HttpServletRequest request, @RequestBody PasswordRequest passwordRequest){
        return success(userService.updatePassword(request,passwordRequest));
    }

    @GetMapping("/info")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') OR hasAuthority('ROLE_USER') OR hasAuthority('ROLE_STAFF')")
    ResponseEntity<BaseResponse> infoUser(HttpServletRequest request){
        return success(userService.infoUser(request));
    }

    @GetMapping("/infoUser/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') OR hasAuthority('ROLE_USER') OR hasAuthority('ROLE_STAFF')")
    ResponseEntity<BaseResponse> infoUserById(@PathVariable long id){
        return success(userService.infoById(id));
    }


    @GetMapping("/role")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') OR hasAuthority('ROLE_USER') OR hasAuthority('ROLE_STAFF')")
    ResponseEntity<BaseResponse> getRole(HttpServletRequest request){
        return success(userService.roleUser(request));
    }

    @GetMapping("/getAll-users")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') OR hasAuthority('ROLE_STAFF')")
    ResponseEntity<BaseResponse> getAllUser(@RequestParam int offset, @RequestParam int limit){
        PageRequest pageRequest = PageRequest.of(offset,limit);
        return success(userService.getAll(pageRequest));
    }

    @PutMapping("/update-user")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') OR hasAuthority('ROLE_USER') OR hasAuthority('ROLE_STAFF')")
    ResponseEntity<BaseResponse> updateUser(@RequestBody ProfileRequest profileRequest, HttpServletRequest request){
        return success(userService.updateProfile(request,profileRequest));
    }

    @GetMapping("/total-user")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') ")
    ResponseEntity<BaseResponse> getTotalUser(){
        return success(userService.getTotalUser());
    }

    @PutMapping("/add-company/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') ")
    ResponseEntity<BaseResponse> addCompanies(@PathVariable long id, @RequestParam("role") long role){
        userService.addCompany(id,role);
        return success();
    }

    @GetMapping("/all-users")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    ResponseEntity<BaseResponse> changeStatus(){
        return success(userService.getUsers());
    }

    @PutMapping("/changeStatus/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    ResponseEntity<BaseResponse> changeStatus(@PathVariable long id, @RequestParam("status") long status){
        userService.changeStatusAccount(id,status);
        return success();
    }

    @GetMapping("/get-roles")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') OR hasAuthority('ROLE_USER') OR hasAuthority('ROLE_STAFF')")
    ResponseEntity<BaseResponse> getInfoRoles(HttpServletRequest request){
        return success(userService.getRole(request));
    }

    @PostMapping("/uploadImage")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') OR hasAuthority('ROLE_USER') OR hasAuthority('ROLE_STAFF')")
    ResponseEntity<BaseResponse> uploadImage(HttpServletRequest request, @RequestParam("file") MultipartFile file){
        return success(userService.updateImage(request,file));
    }

    @GetMapping("/get-cvs-user/{id}")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    ResponseEntity<BaseResponse> getCvUser(@PathVariable long id){
        return success(userService.getCvs(id));
    }

    @GetMapping("/get-all-favourite/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') OR hasAuthority('ROLE_USER') OR hasAuthority('ROLE_STAFF')")
    ResponseEntity<BaseResponse> getAllJobFavourite(@PathVariable long id){
        return success(userService.getJobFavorite(id));
    }

    @GetMapping("/add-job-favourite/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') OR hasAuthority('ROLE_USER') OR hasAuthority('ROLE_STAFF')")
    ResponseEntity<BaseResponse> addJobFavourite(@PathVariable long id, @RequestParam long idNew){
        userService.addNewFavourite(id,idNew);
        return success();
    }

    @GetMapping("/user-cv/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') OR hasAuthority('ROLE_USER') OR hasAuthority('ROLE_STAFF')")
    ResponseEntity<BaseResponse> statusCv(@PathVariable Long id){
        return success(cvService.myListCv(id));
    }





}
