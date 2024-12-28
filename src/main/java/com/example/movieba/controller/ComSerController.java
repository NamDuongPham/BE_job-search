package com.example.movieba.controller;

import com.example.movieba.model.response.BaseResponse;
import com.example.movieba.service.CompanySerService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@AllArgsConstructor
@RequestMapping("/api/v2")
public class ComSerController extends BaseController{
    private final CompanySerService companySerService;

    @GetMapping("/buy-services")
    @PreAuthorize("hasAuthority('ROLE_STAFF')")
    ResponseEntity<BaseResponse> buyServices(@RequestParam long serviceId, @RequestParam long comId){
        companySerService.buyService(serviceId,comId);
        return success();
    }

    @GetMapping("/all-buy-services/{id}")
    @PreAuthorize("hasAuthority('ROLE_STAFF')")
    ResponseEntity<BaseResponse> allBuyServices(@PathVariable long id){
        return success(companySerService.getAllByIdCom(id));
    }


}
