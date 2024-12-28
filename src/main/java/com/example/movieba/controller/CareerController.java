package com.example.movieba.controller;

import com.example.movieba.model.request.career.CareerRequest;
import com.example.movieba.model.response.BaseResponse;
import com.example.movieba.service.CareerService;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@AllArgsConstructor
@RequestMapping("/api/v2")
public class CareerController extends BaseController {
    private final CareerService careerService;

    @PostMapping ("/add-career")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    ResponseEntity<BaseResponse> addCareer(@RequestBody CareerRequest careerRequest){
        careerService.createCareer(careerRequest.getNameCareer());
        return success();
    }

    @PutMapping ("/update-career/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    ResponseEntity<BaseResponse> updateCareer(@PathVariable long id,@RequestBody CareerRequest careerRequest){
        careerService.updateCareer(id,careerRequest.getNameCareer());
        return success();
    }

    @DeleteMapping("/delete-career/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    ResponseEntity<BaseResponse> deleteCareer(@PathVariable long id){
        careerService.deleteCareer(id);
        return success();
    }

}
