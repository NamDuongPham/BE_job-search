package com.example.movieba.controller;


import com.example.movieba.model.request.location.LocationRequest;
import com.example.movieba.model.response.BaseResponse;
import com.example.movieba.service.LocationService;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@AllArgsConstructor
@RequestMapping("/api/v2")
public class LocationController extends BaseController {
    private final LocationService locationService;

    @PostMapping("/add-location")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    ResponseEntity<BaseResponse> addCareer(@RequestBody LocationRequest locationRequest){
        locationService.createLocation(locationRequest.getNameLocation());
        return success();
    }

        @PutMapping("/update-location/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    ResponseEntity<BaseResponse> updateCareer(@PathVariable long id,@RequestBody LocationRequest locationRequest){
       locationService.updateLocation(id, locationRequest.getNameLocation());
        return success();
    }

    @DeleteMapping("/delete-location/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    ResponseEntity<BaseResponse> deleteLocation(@PathVariable long id){
        locationService.deleteLocation(id);
        return success();
    }


}
