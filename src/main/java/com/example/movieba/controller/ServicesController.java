package com.example.movieba.controller;

import com.example.movieba.model.request.services.ServicesRequest;
import com.example.movieba.model.request.user.PasswordRequest;
import com.example.movieba.model.response.BaseResponse;
import com.example.movieba.service.ServicesRe;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@AllArgsConstructor
@RequestMapping("/api/v2")
public class ServicesController extends BaseController{
    private ServicesRe servicesRe;

    @PostMapping("/create-service")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    ResponseEntity<BaseResponse> createServices(@RequestBody ServicesRequest servicesRequest){
        servicesRe.createServices(servicesRequest);
        return success();
    }


    @PutMapping ("/update-service/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    ResponseEntity<BaseResponse> updateServices(@PathVariable long id, @RequestBody ServicesRequest servicesRequest){
        servicesRe.updateServices(id,servicesRequest);
        return success();
    }

    @DeleteMapping("/delete-service/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    ResponseEntity<BaseResponse> deleteServices(@PathVariable long id){
        servicesRe.deleteServices(id);
        return success();
    }

    @GetMapping ("/get-service")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') OR hasAuthority('ROLE_STAFF')")
    ResponseEntity<BaseResponse> getServices(){
        return success(servicesRe.getAllServices());
    }



}
