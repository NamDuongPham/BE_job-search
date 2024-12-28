package com.example.movieba.controller;

import com.example.movieba.model.request.json.DataSave;
import com.example.movieba.model.response.BaseResponse;
import com.example.movieba.model.response.cv.CvRequest;
import com.example.movieba.service.CvService;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@AllArgsConstructor
@RequestMapping("/api/v2")
public class CvController extends BaseController{

    private final CvService cvService;


    @GetMapping("/total-cvs")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    ResponseEntity<BaseResponse> totalCvs(){
        return success(cvService.getTotalCvs());
    }

    @GetMapping("/getAll-cvs")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    ResponseEntity<BaseResponse> getAllCvs(){
        return success(cvService.getAllCvs());
    }

    @GetMapping("/get-cvs/{id}")
    @PreAuthorize("hasAuthority('ROLE_STAFF')")
    ResponseEntity<BaseResponse> getCvs(@PathVariable long id){
        return success(cvService.getByCvsByIdNew(id));
    }


    @PostMapping("/add-cv/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') OR hasAuthority('ROLE_USER') OR hasAuthority('ROLE_STAFF')")
    ResponseEntity<BaseResponse> createCv(@PathVariable long id, @RequestBody CvRequest cvRequest){
        return success(cvService.addCv(id,cvRequest));
    }

    @PutMapping("/change-security/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') OR hasAuthority('ROLE_USER') OR hasAuthority('ROLE_STAFF')")
    ResponseEntity<BaseResponse> changeSecurity(@PathVariable long id, @RequestParam String security){
        cvService.changeSecurity(id,security);
        return success();
    }

    @GetMapping("/search-cv")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') OR hasAuthority('ROLE_USER') OR hasAuthority('ROLE_STAFF')")
    ResponseEntity<BaseResponse> searchCv(@RequestParam String keyWord, @RequestParam Long locationId, @RequestParam Long careerId){
        return success(cvService.findCvs(keyWord,careerId,locationId));
    }

    @GetMapping("/cv-public")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') OR hasAuthority('ROLE_USER') OR hasAuthority('ROLE_STAFF')")
    ResponseEntity<BaseResponse> searchCvPublic(){
        return success(cvService.findCvsPublic());
    }

    @DeleteMapping("/delete-cv/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') OR hasAuthority('ROLE_USER') OR hasAuthority('ROLE_STAFF')")
    ResponseEntity<BaseResponse> deleteCv(@PathVariable long id, @RequestParam long idUser){
        cvService.deleteCv(idUser,id);
        return success();
    }

    @PutMapping("/update-list-cv/{idNew}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') OR hasAuthority('ROLE_STAFF')")
    ResponseEntity<BaseResponse> updateListCv(@PathVariable Long idNew, @RequestBody DataSave dataSave){
        cvService.changeActionCv(idNew,dataSave.getId(), dataSave.getStatus(),dataSave.getContent());
        return success();
    }
}
