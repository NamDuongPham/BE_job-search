package com.example.movieba.controller.userpub;

import com.example.movieba.controller.BaseController;
import com.example.movieba.model.response.BaseResponse;
import com.example.movieba.repository.CareerRepository;
import com.example.movieba.service.CareerService;
import com.example.movieba.service.LocationService;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AllArgsConstructor
@RequestMapping("/api/v1")
public class LocationPublicController extends BaseController {

    private final LocationService locationService;
    private final CareerService careerService;

    @GetMapping("/all-location")
    ResponseEntity<BaseResponse> allLocation(){
        return success(locationService.getAll());
    }

    @GetMapping("/all-career")
    ResponseEntity<BaseResponse> allCareer(){
        return success(careerService.getAllCareer());
    }

}
